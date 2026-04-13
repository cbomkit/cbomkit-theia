// Copyright 2024 PQCA
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"io"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"strings"

	"github.com/cbomkit/cbomkit-theia/provider/filesystem"
	"github.com/cbomkit/cbomkit-theia/scanner/pem"
	"github.com/cbomkit/cbomkit-theia/scanner/plugins"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/report"
)

func NewSecretsPlugin() (plugins.Plugin, error) {
	return &Plugin{}, nil
}

type Plugin struct{}

func (*Plugin) GetName() string {
	return "Secret Detection Plugin"
}

func (*Plugin) GetExplanation() string {
	return "Find Secrets & Keys"
}

func (*Plugin) GetType() plugins.PluginType {
	return plugins.PluginTypeAppend
}

type findingWithMetadata struct {
	report.Finding
	raw []byte
}

func (*Plugin) UpdateBOM(fs filesystem.Filesystem, bom *cdx.BOM) error {
	detector, err := detect.NewDetectorDefaultConfig()
	if err != nil {
		return err
	}
	// Detect findings
	components := make([]cdx.Component, 0)
	if err := fs.WalkDir(func(path string) error {
		// Skip large files
		maxFileSize := viper.GetInt64("keys.max_file_size")
		if maxFileSize <= 0 {
			maxFileSize = 1024 * 1024 // Default to 1MB
		}

		readCloser, err := fs.Open(path)
		if err != nil {
			return nil // skip and continue
		}
		defer readCloser.Close()

		limitReader := io.LimitReader(readCloser, maxFileSize+1)
		content, err := io.ReadAll(limitReader)
		if err != nil {
			log.WithField("path", path).Warn("Unable to read file")
			return nil
		}

		// Skip large files
		if int64(len(content)) > maxFileSize {
			log.Warnf("Skipping large file: %s (exceeds limit of %d bytes)", path, maxFileSize)
			return nil
		}

		fragment := detect.Fragment{Raw: string(content), FilePath: path}
		for _, finding := range detector.Detect(fragment) {
			findingMeta := findingWithMetadata{
				Finding: finding,
				raw:     content,
			}
			log.WithFields(log.Fields{
				"type": finding.RuleID, "file": finding.File,
			}).Info("Secret detected")

			// Create CDX Components
			currentComponents, err := findingMeta.getComponents()
			if err != nil {
				log.WithError(err).Warn("Could not add secret finding to BOM component")
				continue
			}
			components = append(components, currentComponents...)
		}
		return nil
	}); err != nil {
		log.WithError(err).Error("Error while trying to scan for secrets")
		return err
	}

	if len(components) == 0 {
		log.Info("No secrets found.")
		return nil
	}

	// Write  bom
	*bom.Components = append(*bom.Components, components...)
	return nil
}

func (finding findingWithMetadata) getComponents() ([]cdx.Component, error) {
	switch finding.RuleID {
	case "private-key":
		return finding.getPrivateKeyComponent()
	}
	return []cdx.Component{finding.getGenericSecretComponent()}, nil
}

func (finding findingWithMetadata) getPrivateKeyComponent() ([]cdx.Component, error) {
	// Filter for private keys only
	privateKeyFilter := pem.Filter{
		FilterType: pem.TypeAllowlist,
		List: []pem.BlockType{
			pem.BlockTypePrivateKey,
			pem.BlockTypeEncryptedPrivateKey,
			pem.BlockTypeRSAPrivateKey,
			pem.BlockTypeECPrivateKey,
			pem.BlockTypeOPENSSHPrivateKey,
		},
	}

	// Parse PEM blocks
	blocks := pem.ParsePEMToBlocksWithTypeFilter(finding.raw, privateKeyFilter)
	if len(blocks) == 0 {
		return []cdx.Component{finding.getGenericSecretComponent()}, nil
	}

	log.Infof("Found %d private key(s) in %s", len(blocks), finding.File)

	components := make([]cdx.Component, 0)
	for block := range blocks {
		currentComponents, err := pem.GenerateCdxComponents(block)
		if err != nil {
			continue
		}

		for i := range currentComponents {
			description := currentComponents[i].Description
			if description != "" {
				currentComponents[i].Description = strings.Join([]string{description, finding.Description}, ";")
			} else {
				currentComponents[i].Description = finding.Description
			}
			currentComponents[i].Evidence = &cdx.Evidence{
				Occurrences: &[]cdx.EvidenceOccurrence{
					{
						Location: finding.File,
						Line:     &finding.StartLine,
					},
				},
			}
		}
		components = append(components, currentComponents...)
	}
	return components, nil
}

func (finding findingWithMetadata) getGenericSecretComponent() cdx.Component {
	return cdx.Component{
		Name:        finding.RuleID,
		Description: finding.Description,
		Type:        cdx.ComponentTypeCryptographicAsset,
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
			RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
				Type: getRelatedCryptoAssetTypeFromRuleID(finding.RuleID),
			},
		},
		Evidence: &cdx.Evidence{
			Occurrences: &[]cdx.EvidenceOccurrence{
				{
					Location: finding.File,
					Line:     &finding.StartLine,
				},
			},
		},
	}
}

func getRelatedCryptoAssetTypeFromRuleID(id string) cdx.RelatedCryptoMaterialType {
	switch {
	case strings.Contains(id, "private-key"):
		return cdx.RelatedCryptoMaterialTypePrivateKey
	case strings.Contains(id, "token") ||
		strings.Contains(id, "jwt"):
		return cdx.RelatedCryptoMaterialTypeToken
	case strings.Contains(id, "key"):
		return cdx.RelatedCryptoMaterialTypeKey
	case strings.Contains(id, "password"):
		return cdx.RelatedCryptoMaterialTypePassword
	default:
		return cdx.RelatedCryptoMaterialTypeUnknown
	}
}
