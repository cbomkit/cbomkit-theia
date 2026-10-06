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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/cbomkit/cbomkit-theia/provider/cyclonedx"
	"github.com/cbomkit/cbomkit-theia/provider/filesystem"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zricethezav/gitleaks/v8/detect"
)

func TestConfiguredFileSizeSurvivesGitleaksInitialization(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	viper.SetConfigType("yaml")
	if err := viper.ReadConfig(strings.NewReader("keys:\n  max_file_size: 2097152\nscanner:\n  marker: preserved\n")); err != nil {
		t.Fatal(err)
	}

	key, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "private_key", "dir", "rsa.pem"))
	if err != nil {
		t.Fatal(err)
	}
	content := append(key, bytes.Repeat([]byte("x"), 1<<20)...)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "large-key.pem"), content, 0600); err != nil {
		t.Fatal(err)
	}

	components := []cdx.Component{}
	bom := &cdx.BOM{Components: &components}
	if err := (&Plugin{}).UpdateBOM(filesystem.NewPlainFilesystem(dir), bom); err != nil {
		t.Fatal(err)
	}
	assert.NotEmpty(t, components, "secret in a file above the default 1 MB limit should be detected")
	assert.EqualValues(t, 2<<20, viper.GetInt64("keys.max_file_size"))
	assert.Equal(t, "preserved", viper.GetString("scanner.marker"))
}

func TestUpdateBOMScansNodeModulesUnlessIgnored(t *testing.T) {
	root := t.TempDir()
	key, err := os.ReadFile("../../../testdata/secrets/dir/rsa/ssh_rsa")
	if err != nil {
		t.Fatal(err)
	}
	paths := []string{
		"node_modules/example/secret.js",
		"node_modules_1/example/secret.js",
	}
	for _, path := range paths {
		fullPath := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fullPath, key, 0600); err != nil {
			t.Fatal(err)
		}
	}

	scan := func(fs filesystem.Filesystem) map[string]bool {
		bom := cdx.NewBOM()
		components := []cdx.Component{}
		bom.Components = &components
		if err := (&Plugin{}).UpdateBOM(fs, bom); err != nil {
			t.Fatal(err)
		}
		found := make(map[string]bool)
		for _, component := range *bom.Components {
			for _, occurrence := range *component.Evidence.Occurrences {
				found[occurrence.Location] = true
			}
		}
		return found
	}

	plain := filesystem.NewPlainFilesystem(root)
	found := scan(plain)
	assert.True(t, found[paths[0]], "secret under node_modules must be detected")
	assert.True(t, found[paths[1]], "control secret must be detected")

	filtered := filesystem.NewFilteredFilesystem(plain, []string{"node_modules/"})
	found = scan(filtered)
	assert.False(t, found[paths[0]], "explicitly ignored path must remain excluded")
	assert.True(t, found[paths[1]], "control secret must still be detected")
}

func TestPrivateKey(t *testing.T) {
	detector, err := detect.NewDetectorDefaultConfig()
	if err != nil {
		t.Fail()
		return
	}

	privateKeyRaw := "-----BEGIN PRIVATE KEY-----\nMIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCfaDB7pK/fmP/I\n7IusSK8lTCBnPZghqIbVLt2QHYAMoEF1CaF4F4rxo2vl1Mt8gwsq4T3osQFZMvnL\nYHb7KNyUoJgTjLxJQADv2u4Q3U38heAzK5Tp4ry4MCnuyJIqAPK1GiruwEq4zQrx\n+WzVix8otO37SuW9tzklqlNGMiAYBL0TBKHvS5XMbjP1idBMB8erMz29w/TVQnEB\nKj0vCdZjrbVPKygptt5kcSrL5f4xCZwU+ufz7cp0GLwpRMJ+shG9YJJFBxb0itPF\nsy51vAyEtdBC7jgAU96ZVeQ06nryDq1D2EpoVMElqNyL46Jo3lnKbGquGKzXzQYU\nBN32/scDAgMBAAECggEBAJE/mo3PLgILo2YtQ8ekIxNVHmF0Gl7w9IrjvTdH6hmX\nHI3MTLjkmtI7GmG9V/0IWvCjdInGX3grnrjWGRQZ04QKIQgPQLFuBGyJjEsJm7nx\nMqztlS7YTyV1nX/aenSTkJO8WEpcJLnm+4YoxCaAMdAhrIdBY71OamALpv1bRysa\nFaiCGcemT2yqZn0GqIS8O26Tz5zIqrTN2G1eSmgh7DG+7FoddMz35cute8R10xUG\nhF5YU+6fcXiRQ/Kh7nlxelPGqdZFPMk7LpVHzkQKwdJ+N0P23lPDIfNsvpG1n0OP\n3g5km7gHSrSU2yZ3eFl6DB9x1IFNS9BaQQuSxYJtKwECgYEA1C8jjzpXZDLvlYsV\n2jlMzkrbsIrX2dzblVrNsPs2jRbjYU8mg2DUDO6lOhtxHfqZG6sO+gmWi/zvoy9l\nyolGbXe1Jqx66p9fznIcecSwar8+ACa356Wk74Nt1PlBOfCMqaJnYLOLaFJa29Vy\nu5ClZVzKd5AVXl7yFVd4XfLv/WECgYEAwFMMtFoasdF92c0d31rZ1uoPOtFz6xq6\nuQggdm5zzkhnfwUAGqppS/u1CHcJ7T/74++jLbFTsaohGr4jEzWSGvJpomEUChy3\nr25YofMclUhJ5pCEStsLtqiCR1Am6LlI8HMdBEP1QDgEC5q8bQW4+UHuew1E1zxz\nosZOhe09WuMCgYEA0G9aFCnwjUqIFjQiDFP7gi8BLqTFs4uE3Wvs4W11whV42i+B\nms90nxuTjchFT3jMDOT1+mOO0wdudLRr3xEI8SIF/u6ydGaJG+j21huEXehtxIJE\naDdNFcfbDbqo+3y1ATK7MMBPMvSrsoY0hdJq127WqasNgr3sO1DIuima3SECgYEA\nnkM5TyhekzlbIOHD1UsDu/D7+2DkzPE/+oePfyXBMl0unb3VqhvVbmuBO6gJiSx/\n8b//PdiQkMD5YPJaFrKcuoQFHVRZk0CyfzCEyzAts0K7XXpLAvZiGztriZeRjSz7\nsrJnjF0H8oKmAY6hw+1Tm/n/b08p+RyL48TgVSE2vhUCgYA3BWpkD4PlCcn/FZsq\nOrLFyFXI6jIaxskFtsRW1IxxIlAdZmxfB26P/2gx6VjLdxJI/RRPkJyEN2dP7CbR\nBDjb565dy1O9D6+UrY70Iuwjz+OcALRBBGTaiF2pLn6IhSzNI2sy/tXX8q8dBlg9\nOFCrqT/emes3KytTPfa5NZtYeQ==\n-----END PRIVATE KEY-----"

	fragment := detect.Fragment{Raw: privateKeyRaw, FilePath: "key.pem"}
	findings := detector.Detect(fragment)
	assert.Len(t, findings, 1)

	privateKey := findings[0]
	assert.Equal(t, privateKey.RuleID, "private-key")

	findingWithMeta := findingWithMetadata{
		Finding: privateKey,
		raw:     []byte(privateKeyRaw),
	}

	components, err := findingWithMeta.getComponents()
	if err != nil {
		t.Error(err)
		return
	}
	assert.Len(t, components, 1)
	keyComponent := components[0]

	bom := cdx.NewBOM()
	cyclonedx.AddComponents(bom, components)
	err = cdx.NewBOMEncoder(os.Stdout, cdx.BOMFileFormatJSON).SetPretty(true).Encode(bom)
	if err != nil {
		t.Fail()
		return
	}
	assert.Equal(t, keyComponent.Name, "RSA-2048")
	assert.Equal(t, keyComponent.CryptoProperties.RelatedCryptoMaterialProperties.Type, cdx.RelatedCryptoMaterialTypePrivateKey)
	assert.Equal(t, *keyComponent.CryptoProperties.RelatedCryptoMaterialProperties.Size, 2048)
	assert.Equal(t, keyComponent.CryptoProperties.OID, "1.2.840.113549.1.1.1")
}

// A PEM block recognized as a private key type whose body cannot be parsed (e.g. because it is
// password-encrypted) must still be reported as a generic secret rather than dropped entirely.
func TestEncryptedPrivateKeyFallsBackToGenericSecret(t *testing.T) {
	detector, err := detect.NewDetectorDefaultConfig()
	if err != nil {
		t.Fail()
		return
	}

	encryptedPrivateKeyRaw := "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: DES-EDE3-CBC,BA26229A1653B7FF\n\n2i5PgUsjTMVjyLog9C0BgFyMOBAujM3zwSAr4W2vsIjMHY2Rm4gtLQ0hIhc8dGWH\nJXOAK67UlwiXwmVfbXqI4G3AZS0i5r+wIugRxjejWFRMEubvsMd5D8vqHmYhoBM+\nOw+PmVwq9pRXQhIWuUBznHevWZeSFHmSjcSlM9BFV2rn3zvS4bMoIU00OoZplVKp\n-----END RSA PRIVATE KEY-----"

	fragment := detect.Fragment{Raw: encryptedPrivateKeyRaw, FilePath: "encrypted-key.pem"}
	findings := detector.Detect(fragment)
	assert.Len(t, findings, 1)
	assert.Equal(t, findings[0].RuleID, "private-key")

	findingWithMeta := findingWithMetadata{
		Finding: findings[0],
		raw:     []byte(encryptedPrivateKeyRaw),
	}

	components, err := findingWithMeta.getComponents()
	if err != nil {
		t.Error(err)
		return
	}
	// The encrypted-key component, plus a standalone algorithm component for its cipher
	// referenced via SecuredBy.AlgorithmRef.
	assert.Len(t, components, 2)
	assert.Equal(t, components[0].CryptoProperties.AssetType, cdx.CryptoAssetTypeRelatedCryptoMaterial)
	assert.Equal(t, components[0].CryptoProperties.RelatedCryptoMaterialProperties.Type, cdx.RelatedCryptoMaterialTypePrivateKey)
}

// testKeyPEMs holds synthetic PEM encodings of one RSA and one ECDSA key pair.
type testKeyPEMs struct {
	rsaPrivate, rsaPublic, ecPrivate, ecPublic string
}

var (
	testKeysOnce sync.Once
	testKeys     testKeyPEMs
)

func syntheticKeys(t *testing.T) testKeyPEMs {
	t.Helper()
	testKeysOnce.Do(func() {
		encode := func(blockType string, der []byte, err error) string {
			if err != nil {
				t.Fatal(err)
			}
			return string(pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}))
		}
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(rsaKey)
		testKeys.rsaPrivate = encode("PRIVATE KEY", der, err)
		der, err = x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
		testKeys.rsaPublic = encode("PUBLIC KEY", der, err)
		der, err = x509.MarshalPKCS8PrivateKey(ecKey)
		testKeys.ecPrivate = encode("PRIVATE KEY", der, err)
		der, err = x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
		testKeys.ecPublic = encode("PUBLIC KEY", der, err)
	})
	return testKeys
}

// scanFiles writes files (relative path -> content) to a temp dir and runs the secrets plugin on it.
func scanFiles(t *testing.T, files map[string]string) []cdx.Component {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		full := filepath.Join(root, filepath.FromSlash(name))
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0755))
		require.NoError(t, os.WriteFile(full, []byte(content), 0600))
	}
	components := []cdx.Component{}
	bom := &cdx.BOM{Components: &components}
	require.NoError(t, (&Plugin{}).UpdateBOM(filesystem.NewPlainFilesystem(root), bom))
	return *bom.Components
}

// describe renders a component as "<name>/<related material type>@<file>:<line>".
func describe(c cdx.Component) string {
	related := c.CryptoProperties.RelatedCryptoMaterialProperties
	occurrence := (*c.Evidence.Occurrences)[0]
	return fmt.Sprintf("%s/%s@%s:%d", c.Name, related.Type, occurrence.Location, *occurrence.Line)
}

func describeAll(components []cdx.Component) []string {
	out := make([]string, 0, len(components))
	for _, c := range components {
		out = append(out, describe(c))
	}
	sort.Strings(out)
	return out
}

// Gitleaks' `[extend] useDefault = true` stops extending from the third config load onward, which
// used to drop every default rule (component counts 2, 2, 0, 0, ...). The detector must behave
// identically no matter how many times it is built, while also keeping #223 (no implicit path
// exclusions) and #224 (the application's Viper configuration is preserved).
func TestRepeatedScansKeepDefaultAndExtraRules(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	viper.SetConfigType("yaml")
	require.NoError(t, viper.ReadConfig(strings.NewReader("keys:\n  max_file_size: 2097152\nscanner:\n  marker: preserved\n")))

	rsaFixture, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "private_key", "dir", "rsa.pem"))
	require.NoError(t, err)
	keys := syntheticKeys(t)
	files := map[string]string{
		"rsa.pem":                         string(rsaFixture),
		"public.pem":                      keys.ecPublic,
		"node_modules/example/secret.pem": string(rsaFixture),
	}

	var baseline []string
	for i := 1; i <= 6; i++ {
		detector, err := newSecretsDetector()
		require.NoError(t, err)
		for _, ruleID := range []string{"private-key", "aws-access-token", "pem-public-key", "public-key-file"} {
			assert.Contains(t, detector.Config.Rules, ruleID, "scan %d is missing rule %s", i, ruleID)
		}

		got := describeAll(scanFiles(t, files))
		if i == 1 {
			baseline = got
			require.NotEmpty(t, baseline)
			assert.Contains(t, strings.Join(baseline, "\n"), "@node_modules/example/secret.pem", "node_modules must be scanned")
			assert.Contains(t, strings.Join(baseline, "\n"), "ECDSA/public-key@public.pem")
			continue
		}
		assert.Equal(t, baseline, got, "scan %d differs from scan 1", i)
	}

	assert.EqualValues(t, 2<<20, viper.GetInt64("keys.max_file_size"))
	assert.Equal(t, "preserved", viper.GetString("scanner.marker"))
}

func TestExtraRuleMergesIntoDefaultRuleWithSameID(t *testing.T) {
	base, err := newDetectorWithExtraRules("")
	require.NoError(t, err)
	original := base.Config.Rules["private-key"]
	require.NotNil(t, original.Regex)

	t.Run("unset fields keep the default, lists are appended", func(t *testing.T) {
		detector, err := newDetectorWithExtraRules("[[rules]]\nid = \"private-key\"\ndescription = \"custom\"\nkeywords = [\"extra-keyword\"]\n")
		require.NoError(t, err)
		merged := detector.Config.Rules["private-key"]
		assert.Equal(t, "custom", merged.Description)
		assert.Equal(t, original.Regex.String(), merged.Regex.String())
		assert.Equal(t, append(append([]string{}, original.Keywords...), "extra-keyword"), merged.Keywords)
		assert.Len(t, detector.Config.Rules, len(base.Config.Rules))
	})

	t.Run("set fields replace the default", func(t *testing.T) {
		detector, err := newDetectorWithExtraRules("[[rules]]\nid = \"private-key\"\nregex = '''replacement'''\n")
		require.NoError(t, err)
		assert.Equal(t, "replacement", detector.Config.Rules["private-key"].Regex.String())
	})
}

func TestMultipleKeysInOneFileYieldOneComponentEach(t *testing.T) {
	keys := syntheticKeys(t)
	// Gitleaks numbers lines from 0, so a key's reported line is the number of lines before it.
	linesBefore := func(preceding string) int { return strings.Count(preceding, "\n") }

	t.Run("two private keys", func(t *testing.T) {
		got := describeAll(scanFiles(t, map[string]string{"both.pem": keys.rsaPrivate + keys.ecPrivate}))
		assert.Equal(t, []string{
			fmt.Sprintf("ECDSA/private-key@both.pem:%d", linesBefore(keys.rsaPrivate)),
			"RSA-2048/private-key@both.pem:0",
		}, got)
	})

	t.Run("public keys of different algorithms", func(t *testing.T) {
		got := describeAll(scanFiles(t, map[string]string{"pub.pem": keys.rsaPublic + keys.ecPublic}))
		assert.Equal(t, []string{
			fmt.Sprintf("ECDSA/public-key@pub.pem:%d", linesBefore(keys.rsaPublic)),
			"RSA-2048/public-key@pub.pem:0",
		}, got)
	})

	t.Run("same key twice is reported twice, not four times", func(t *testing.T) {
		got := scanFiles(t, map[string]string{"dup.pem": keys.rsaPublic + "\n" + keys.rsaPublic})
		assert.Len(t, got, 2)
	})

	t.Run("an unparsable block does not drop its neighbours", func(t *testing.T) {
		corrupt := "-----BEGIN PUBLIC KEY-----\nbm90IGEga2V5IGF0IGFsbCwganVzdCBieXRlcyE=\n-----END PUBLIC KEY-----\n"
		got := describeAll(scanFiles(t, map[string]string{"mixed.pem": keys.rsaPublic + corrupt + keys.ecPublic}))
		assert.Equal(t, []string{
			fmt.Sprintf("ECDSA/public-key@mixed.pem:%d", linesBefore(keys.rsaPublic+corrupt)),
			"RSA-2048/public-key@mixed.pem:0",
			fmt.Sprintf("pem-public-key/key@mixed.pem:%d", linesBefore(keys.rsaPublic)),
		}, got)
	})
}

func TestPublicKeyFileFallback(t *testing.T) {
	keys := syntheticKeys(t)

	t.Run("raw file without PEM markers is flagged by its extension", func(t *testing.T) {
		got := scanFiles(t, map[string]string{"host.pub": "\x30\x59\x30\x13\x06\x07"})
		require.Len(t, got, 1)
		assert.Equal(t, "public-key-file", got[0].Name)
	})

	t.Run("PEM content supersedes the extension rule", func(t *testing.T) {
		got := scanFiles(t, map[string]string{"host.pub": keys.ecPublic})
		require.Len(t, got, 1)
		assert.Equal(t, "ECDSA", got[0].Name)
	})
}
