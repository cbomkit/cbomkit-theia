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

package javasecurity

import (
	"fmt"
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/magiconair/properties"
	"github.com/stretchr/testify/assert"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

func TestJDKPath(t *testing.T) {
	type args struct {
		dockerConfig v1.Config
	}
	tests := []struct {
		name      string
		args      args
		wantValue string
		wantOk    bool
	}{
		{
			name: "Test 1",
			args: args{
				dockerConfig: v1.Config{
					Cmd: []string{"java", "-jar", "app.jar"},
				},
			},
			wantValue: "",
			wantOk:    false,
		},
		{
			name: "Test 2",
			args: args{
				dockerConfig: v1.Config{
					Cmd: []string{"java", "-jar", "app.jar"},
					Env: []string{"JAVA_HOME=/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.292.b10-0.el8_4.x86_64"},
				},
			},
			wantValue: "/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.292.b10-0.el8_4.x86_64",
			wantOk:    true,
		},
		{
			name: "Test 3",
			args: args{
				dockerConfig: v1.Config{
					Cmd: []string{"/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.292.b10-0.el8_4.x86_64/bin/java", "-jar", "app.jar"},
				},
			},
			wantValue: "/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.292.b10-0.el8_4.x86_64",
			wantOk:    true,
		},
		{
			name: "Test 4",
			args: args{
				dockerConfig: v1.Config{
					Entrypoint: []string{"/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.292.b10-0.el8_4.x86_64/bin/java", "-jar", "app.jar"},
				},
			},
			wantValue: "/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.292.b10-0.el8_4.x86_64",
			wantOk:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotValue, gotOk := getJDKPath(tt.args.dockerConfig)
			if gotValue != tt.wantValue {
				t.Errorf("getJDKPathFromRunCommand() gotValue = %v, want %v", gotValue, tt.wantValue)
			}
			if gotOk != tt.wantOk {
				t.Errorf("getJDKPathFromRunCommand() gotOk = %v, want %v", gotOk, tt.wantOk)
			}
		})
	}
}

func TestExtractTLSRules(t *testing.T) {
	t.Run("Extracting TLS Rules from security file", func(t *testing.T) {
		props := properties.NewProperties()
		_, _, err := props.Set("jdk.tls.disabledAlgorithms", "SHA384, RSA keySize == 3")
		if err != nil {
			t.Error("could not prepare java.security file")
		}

		javaSecurity := New(*props, "java.security")
		restrictions, err := javaSecurity.extractTLSRules()
		javaSecurity.tlsDisabledAlgorithms = restrictions

		assert.NoError(t, err)
		assert.Len(t, javaSecurity.tlsDisabledAlgorithms, 2)
		for _, res := range javaSecurity.tlsDisabledAlgorithms {
			switch res.algorithm {
			case "RSA":
				assert.Equal(t, res.keySizeOperator, keySizeOperatorEqual)
				assert.Equal(t, res.keySize, 3)
			case "SHA384":
				assert.Equal(t, res.keySizeOperator, keySizeOperatorNone)
				assert.Equal(t, res.keySize, 0)
			default:
				assert.FailNow(t, fmt.Sprintf("%v is not a possible algo algorithm", res.algorithm))
			}
		}
	})
}

func TestExtractTLSRulesNotSupported(t *testing.T) {
	t.Run("Extracting TLS Rules from security file", func(t *testing.T) {
		props := properties.NewProperties()
		_, _, err := props.Set("jdk.tls.disabledAlgorithms", "SHA384, RSA jdkCA")
		if err != nil {
			t.Error("could not prepare java.security file")
		}

		javaSecurity := New(*props, "java.security")
		restrictions, err := javaSecurity.extractTLSRules()
		javaSecurity.tlsDisabledAlgorithms = restrictions

		assert.NoError(t, err)
		assert.Len(t, javaSecurity.tlsDisabledAlgorithms, 1)
		for _, res := range javaSecurity.tlsDisabledAlgorithms {
			switch res.algorithm {
			case "SHA384":
				assert.Equal(t, res.keySizeOperator, keySizeOperatorNone)
				assert.Equal(t, res.keySize, 0)
			default:
				assert.FailNow(t, fmt.Sprintf("%v is not a possible algo algorithm", res.algorithm))
			}
		}
	})
}

func TestExtractTLSRulesIllegalValue1(t *testing.T) {
	t.Run("Extracting TLS Rules from security file", func(t *testing.T) {
		props := properties.NewProperties()
		_, _, err := props.Set("jdk.tls.disabledAlgorithms", "SHA384, RSA keySize keySize")
		if err != nil {
			t.Error("could not prepare java.security file")
		}

		javaSecurity := New(*props, "java.security")
		restrictions, err := javaSecurity.extractTLSRules()
		javaSecurity.tlsDisabledAlgorithms = restrictions

		assert.NoError(t, err)
		assert.Len(t, javaSecurity.tlsDisabledAlgorithms, 1)
	})
}

func TestExtractTLSRulesIllegalValue2(t *testing.T) {
	t.Run("Extracting TLS Rules from security file", func(t *testing.T) {
		props := properties.NewProperties()
		_, _, err := props.Set("jdk.tls.disabledAlgorithms", "SHA384, RSA keySize | 234")
		if err != nil {
			t.Error("could not prepare java.security file")
		}

		javaSecurity := New(*props, "java.security")
		restrictions, err := javaSecurity.extractTLSRules()
		javaSecurity.tlsDisabledAlgorithms = restrictions

		assert.NoError(t, err)
		assert.Len(t, javaSecurity.tlsDisabledAlgorithms, 1)
	})
}

func TestExtractTLSRulesInclude(t *testing.T) {
	t.Run("Extracting TLS Rules from security file", func(t *testing.T) {
		props := properties.NewProperties()
		_, _, err := props.Set("jdk.tls.disabledAlgorithms", "SHA384, RSA keySize == 3, DIDYOUGETME keySize >= 123")
		if err != nil {
			t.Error("could not prepare java.security file")
		}

		javaSecurity := New(*props, "java.security")
		restrictions, err := javaSecurity.extractTLSRules()
		javaSecurity.tlsDisabledAlgorithms = restrictions

		assert.NoError(t, err)
		assert.Len(t, javaSecurity.tlsDisabledAlgorithms, 3)
		for _, res := range javaSecurity.tlsDisabledAlgorithms {
			switch res.algorithm {
			case "RSA":
				assert.Equal(t, res.keySizeOperator, keySizeOperatorEqual)
				assert.Equal(t, res.keySize, 3)
			case "SHA384":
				assert.Equal(t, res.keySizeOperator, keySizeOperatorNone)
				assert.Equal(t, res.keySize, 0)
			case "DIDYOUGETME":
				assert.Equal(t, res.keySizeOperator, keySizeOperatorGreaterEqual)
				assert.Equal(t, res.keySize, 123)
			default:
				assert.FailNow(t, fmt.Sprintf("%v is not a possible algo algorithm", res.algorithm))
			}
		}
	})
}

func TestUpdateComponent(t *testing.T) {
	t.Run("Extracting TLS Rules from security file", func(t *testing.T) {
		props := properties.NewProperties()
		_, _, err := props.Set("jdk.tls.disabledAlgorithms", "SHA384, RSA keySize < 4096")
		if err != nil {
			t.Error("could not prepare java.security file")
		}

		javaSecurity := New(*props, "java.security")
		restrictions, err := javaSecurity.extractTLSRules()
		javaSecurity.tlsDisabledAlgorithms = restrictions

		assert.NoError(t, err)
		assert.Len(t, javaSecurity.tlsDisabledAlgorithms, 2)

		component := cyclonedx.Component{
			Name:   "RSA-2048",
			BOMRef: uuid.New().String(),
			Type:   cyclonedx.ComponentTypeCryptographicAsset,
			Evidence: &cyclonedx.Evidence{
				Occurrences: &[]cyclonedx.EvidenceOccurrence{
					{
						Location: "src/main/java/com/mastercard/developer/utils/EncryptionUtils.java",
					},
				},
			},
			CryptoProperties: &cyclonedx.CryptoProperties{
				AssetType: cyclonedx.CryptoAssetTypeAlgorithm,
				AlgorithmProperties: &cyclonedx.CryptoAlgorithmProperties{
					Primitive:              cyclonedx.CryptoPrimitivePKE,
					ParameterSetIdentifier: "2048",
				},
				OID: "1.2.840.113549.1.1.1",
			},
		}

		err = javaSecurity.updateComponent(&component, &[]cyclonedx.Component{component})
		assert.NoError(t, err)
		assert.Len(t, *component.Properties, 3)
	})
}
