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

package certificates

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"

	"github.com/IBM/cbomkit-theia/provider/cyclonedx"
	"github.com/IBM/cbomkit-theia/scanner/x509"
	log "github.com/sirupsen/logrus"
	"github.com/smallstep/pkcs7"

	"github.com/IBM/cbomkit-theia/provider/filesystem"
	scannererrors "github.com/IBM/cbomkit-theia/scanner/errors"
	pemlib "github.com/IBM/cbomkit-theia/scanner/pem"
	"github.com/IBM/cbomkit-theia/scanner/plugins"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// Plugin to parse certificates from the filesystem
type Plugin struct{}

// GetName Get the name of the plugin
func (*Plugin) GetName() string {
	return "Certificate File Plugin"
}

func (*Plugin) GetExplanation() string {
	return "Find x.509 certificates"
}

// GetType Get the type of the plugin
func (*Plugin) GetType() plugins.PluginType {
	return plugins.PluginTypeAppend
}

// NewCertificatePlugin Parse all certificates from the given filesystem
func NewCertificatePlugin() (plugins.Plugin, error) {
	return &Plugin{}, nil
}

// UpdateBOM Add the found certificates to the slice of components
func (certificatesPlugin *Plugin) UpdateBOM(fs filesystem.Filesystem, bom *cdx.BOM) error {
	var certificates []*x509.CertificateWithMetadata

	// Set GODEBUG to allow negative serial numbers (see https://github.com/golang/go/commit/db13584baedce4909915cb4631555f6dbd7b8c38)
	err := setX509NegativeSerial()
	if err != nil {
		log.Error(err.Error())
	}

	err = fs.WalkDir(
		func(path string) (err error) {
			switch filepath.Ext(path) {
			case ".pem", ".cer", ".cert", ".der", ".ca-bundle", ".crt":
				exists, err := fs.Exists(path)
				if err != nil {
					return err
				} else if !exists {
					log.WithField("path", path).Warning("Certificate does not exist")
					return nil
				}

				readCloser, err := fs.Open(path)
				if err != nil {
					return err
				}
				raw, err := filesystem.ReadAllAndClose(readCloser)
				if err != nil {
					return err
				}
				certs, err := parseX509CertFromPath(raw, path)
				if err != nil {
					return scannererrors.GetParsingFailedAlthoughCheckedError(err, certificatesPlugin.GetName())
				}
				certificates = append(certificates, certs...)
			case ".p7a", ".p7b", ".p7c", ".p7r", ".p7s", ".spc":
				exists, err := fs.Exists(path)
				if err != nil {
					return err
				} else if !exists {
					log.WithField("path", path).Warning("Certificate does not exist")
					return nil
				}

				readCloser, err := fs.Open(path)
				if err != nil {
					return err
				}
				raw, err := filesystem.ReadAllAndClose(readCloser)
				if err != nil {
					return err
				}
				certs, err := parsePKCS7FromPath(raw, path)
				if err != nil {
					return scannererrors.GetParsingFailedAlthoughCheckedError(err, certificatesPlugin.GetName())
				}
				certificates = append(certificates, certs...)
			default:
				return nil
			}
			return nil
		})

	if err != nil {
		return err
	}

	// Set GODEBUG to old setting
	err = removeX509NegativeSerial()
	if err != nil {
		log.Error(err.Error())
	}

	log.WithField("numberOfDetectedCertificates", len(certificates)).Info("Certificate searching done")

	for _, cert := range certificates {
		components, dependencyMap, err := x509.GenerateCdxComponents(cert)
		if err != nil {
			log.WithError(err).Error("Error while adding certificate data to bom")
			continue
		}
		cyclonedx.AddComponents(bom, *components)
		cyclonedx.AddDependencies(bom, *dependencyMap)
	}
	return nil
}

// Parse an X.509 certificate from the given path (in base64 PEM or binary DER)
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

// Parse X.509 certificates from a PKCS7 file (base64 PEM format)
func parsePKCS7FromPath(raw []byte, path string) ([]*x509.CertificateWithMetadata, error) {
	block, _ := pem.Decode(raw)

	pkcs7Object, err := pkcs7.Parse(block.Bytes)
	if err != nil || pkcs7Object == nil {
		return make([]*x509.CertificateWithMetadata, 0), err
	}

	certsWithMetadata := make([]*x509.CertificateWithMetadata, 0, len(pkcs7Object.Certificates))

	for _, cert := range pkcs7Object.Certificates {
		certWithMetadata, err := x509.NewX509CertificateWithMetadata(cert, path)
		if err != nil {
			return make([]*x509.CertificateWithMetadata, 0), err
		}
		certsWithMetadata = append(certsWithMetadata, certWithMetadata)
	}

	return certsWithMetadata, nil
}

// Set x509negativeserial=1 in the GODEBUG environment variable.
func setX509NegativeSerial() error {
	godebug := os.Getenv("GODEBUG")
	var newGodebug string

	if strings.Contains(godebug, "x509negativeserial=") {
		// Replace the existing x509negativeserial value with 1
		newGodebug = strings.ReplaceAll(godebug, "x509negativeserial=0", "x509negativeserial=1")
	} else {
		// Append x509negativeserial=1 to the GODEBUG variable
		if godebug != "" {
			newGodebug = godebug + ",x509negativeserial=1"
		} else {
			newGodebug = "x509negativeserial=1"
		}
	}

	// Set the modified GODEBUG environment variable
	return os.Setenv("GODEBUG", newGodebug)
}

// Remove x509negativeserial from the GODEBUG environment variable.
func removeX509NegativeSerial() error {
	godebug := os.Getenv("GODEBUG")
	if godebug == "" {
		return nil // GODEBUG is not set, nothing to remove
	}

	// Split the GODEBUG variable by commas
	parts := strings.Split(godebug, ",")
	var newParts []string

	for _, part := range parts {
		// Skip the part that contains x509negativeserial
		if !strings.HasPrefix(part, "x509negativeserial=") {
			newParts = append(newParts, part)
		}
	}

	// Join the remaining parts back together
	newGodebug := strings.Join(newParts, ",")

	// Set the modified GODEBUG environment variable
	return os.Setenv("GODEBUG", newGodebug)
}
