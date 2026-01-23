// Copyright 2025 PQCA
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

// Package certresolver provides a shared utility for config plugins to resolve
// certificate file paths referenced in configuration files. It reads the actual
// certificate file from the filesystem, parses it using X.509/PEM logic, and
// generates full CycloneDX certificate components with signature algorithms,
// public keys, and dependency relationships.
package certresolver

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/cbomkit/cbomkit-theia/provider/filesystem"
	pemlib "github.com/cbomkit/cbomkit-theia/scanner/pem"
	"github.com/cbomkit/cbomkit-theia/scanner/x509"
	log "github.com/sirupsen/logrus"
)

// ResolveCertificateComponents attempts to read a certificate file at certPath from
// the given filesystem, parse it, and generate full CycloneDX certificate components
// (including signature algorithms, public keys, etc.).
//
// Returns the generated components, a dependency map for internal certificate
// relationships (e.g., cert -> signature algorithm), and the BOMRefs of the
// top-level certificate components (for use in dependsOn relationships from the
// config file component).
//
// If the file cannot be read or parsed, it returns nil slices and no error
// (the caller should fall back to a placeholder component).
func ResolveCertificateComponents(fs filesystem.Filesystem, certPath string) ([]cdx.Component, map[cdx.BOMReference][]string, []string) {
	exists, err := fs.Exists(certPath)
	if err != nil || !exists {
		log.WithField("path", certPath).Debug("Certificate file not found on filesystem, skipping resolution")
		return nil, nil, nil
	}

	rc, err := fs.Open(certPath)
	if err != nil {
		log.WithError(err).WithField("path", certPath).Debug("Cannot open certificate file, skipping resolution")
		return nil, nil, nil
	}
	raw, err := filesystem.ReadAllAndClose(rc)
	if err != nil {
		log.WithError(err).WithField("path", certPath).Debug("Cannot read certificate file, skipping resolution")
		return nil, nil, nil
	}

	certs, err := parseX509CertFromPath(raw, certPath)
	if err != nil || len(certs) == 0 {
		log.WithError(err).WithField("path", certPath).Debug("Cannot parse certificate file, skipping resolution")
		return nil, nil, nil
	}

	allComponents := make([]cdx.Component, 0)
	allDeps := make(map[cdx.BOMReference][]string)
	certBOMRefs := make([]string, 0)

	for _, cert := range certs {
		components, depMap, err := x509.GenerateCdxComponents(cert)
		if err != nil {
			log.WithError(err).WithField("path", certPath).Debug("Error generating CycloneDX components for certificate")
			continue
		}
		if components != nil {
			// Find the certificate component BOMRef (the one with AssetType == Certificate)
			for _, comp := range *components {
				if comp.CryptoProperties != nil && comp.CryptoProperties.AssetType == cdx.CryptoAssetTypeCertificate {
					certBOMRefs = append(certBOMRefs, comp.BOMRef)
				}
			}
			allComponents = append(allComponents, *components...)
		}
		if depMap != nil {
			for k, v := range *depMap {
				allDeps[k] = append(allDeps[k], v...)
			}
		}
	}

	if len(allComponents) == 0 {
		return nil, nil, nil
	}

	return allComponents, allDeps, certBOMRefs
}

// parseX509CertFromPath parses PEM or DER encoded certificates from raw bytes.
// This replicates the logic from the certificates plugin.
func parseX509CertFromPath(raw []byte, path string) ([]*x509.CertificateWithMetadata, error) {
	blocks := pemlib.ParsePEMToBlocksWithTypeFilter(raw, pemlib.Filter{
		FilterType: pemlib.TypeAllowlist,
		List:       []pemlib.BlockType{pemlib.BlockTypeCertificate},
	})

	if len(blocks) == 0 {
		return x509.ParseCertificatesToX509CertificateWithMetadata(raw, path)
	}

	certs := make([]*x509.CertificateWithMetadata, 0, len(blocks))

	for block := range blocks {
		moreCerts, err := x509.ParseCertificatesToX509CertificateWithMetadata(block.Bytes, path)
		if err != nil {
			return moreCerts, err
		}
		certs = append(certs, moreCerts...)
	}

	return certs, nil
}
