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
	"os"
	"path/filepath"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/cbomkit/cbomkit-theia/provider/cyclonedx"
	"github.com/cbomkit/cbomkit-theia/provider/filesystem"
	"github.com/stretchr/testify/assert"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/report"
)

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

// dsaPrivateKeyRaw is a traditional OpenSSL-format DSA private key, generated via:
// openssl dsaparam 1024 | openssl gendsa /dev/stdin
const dsaPrivateKeyRaw = "-----BEGIN DSA PRIVATE KEY-----\n" +
	"MIIBvAIBAAKBgQDvquY4+Og2XpdGr4Ohh2A8i97aSbOT2MsZnKQtfRPAL79Lc6bA\n" +
	"1/FbXCne9UV66S0u4Kw2sfEGl6QoSg+5paGoIkrX4k1NAdRKFomwu4o1ZqVjGvyR\n" +
	"Oc9WJDzZT5ubjSgSs6ZUm2R0D+gJWOanYsmQPNhN/jWYLVUPblVwvGNq3wIVAJVw\n" +
	"Ki31WeGrebE38d2qmzaytgylAoGBAIW16b3eml45cAsmGgSxkcQQ2lNxS4RmlJAV\n" +
	"3JPBdqtqWQaGwKxdcM1zftIRjIFp2tfiBhqKxWzYCQjW7KGo+bDs/UyWz38+VyQf\n" +
	"WK4xNnNluizb1J9ojIu+Z6ENPaKFFlRdjG600Gt6YjjV9wA7OCPRKm+wkDlmbBVW\n" +
	"QYnb8UwxAoGBAKTUzFzLN+pduKGmtNgoskPfqPuht2I/N9qVdT50bbQT2ZNAlah6\n" +
	"4aYCsZbr5dCfyYuM4X5Pe2G9XwHp11hlTv6SldasiiA1YMV8onXLDmKsInkoEn40\n" +
	"CcoN8wIJjxuZXjFHslOuBo+lSXz1f0WhTStt3gsw7a1jTQN1C89ntsO6AhRayeq0\n" +
	"EorEkBsWhQl+1AbpAaPNEA==\n" +
	"-----END DSA PRIVATE KEY-----"

func TestDSAPrivateKeyDetectionAndComponent(t *testing.T) {
	detector, err := detect.NewDetectorDefaultConfig()
	if err != nil {
		t.Fatal(err)
	}

	fragment := detect.Fragment{Raw: dsaPrivateKeyRaw, FilePath: "id_dsa"}
	findings := detector.Detect(fragment)
	assert.Len(t, findings, 1)
	assert.Equal(t, "private-key", findings[0].RuleID)

	findingWithMeta := findingWithMetadata{
		Finding: findings[0],
		raw:     []byte(dsaPrivateKeyRaw),
	}
	components, err := findingWithMeta.getComponents()
	if err != nil {
		t.Fatal(err)
	}
	assert.Len(t, components, 2)

	privKey := components[0]
	assert.Equal(t, "DSA", privKey.Name)
	assert.Equal(t, cdx.RelatedCryptoMaterialTypePrivateKey, privKey.CryptoProperties.RelatedCryptoMaterialProperties.Type)
	assert.NotNil(t, privKey.CryptoProperties.RelatedCryptoMaterialProperties.Size)

	pubKey := components[1]
	assert.Equal(t, "DSA", pubKey.Name)
	assert.Equal(t, cdx.RelatedCryptoMaterialTypePublicKey, pubKey.CryptoProperties.RelatedCryptoMaterialProperties.Type)
	assert.NotEmpty(t, pubKey.CryptoProperties.RelatedCryptoMaterialProperties.Value)
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

// pemCSRRaw is a PKCS#10 certificate signing request generated via:
// openssl req -newkey rsa:2048 -nodes -keyout key.pem -subj "/CN=test.example.com" -out test.csr
const pemCSRRaw = "-----BEGIN CERTIFICATE REQUEST-----\n" +
	"MIICYDCCAUgCAQAwGzEZMBcGA1UEAwwQdGVzdC5leGFtcGxlLmNvbTCCASIwDQYJ\n" +
	"KoZIhvcNAQEBBQADggEPADCCAQoCggEBALUh6Lj+LTzcUUz8TW7sC2l8gdPTXEHL\n" +
	"q5i+v+fttQ+JShh0L/zaM8idDqlnZDoCY5JyknnQcRxpftG6YNM3k1G7JTXVSpiC\n" +
	"rbqvv3z0J90IKBukJX5J2s3YLxxAV1M8tRKmEGSUBg3Ajr8D8r65kIwfamy8bWO/\n" +
	"UHv/x15wkI7Zl89arcCI+xuDXrQLZP7+P8Bk+zxce+YI6qHwgI007bCNHBJI4hCs\n" +
	"C8bOF5cNzL5Knrxmbe0J6B0DHTruuxp/j7o2O0YlnEpTuXAtIkDSNuDXpl0BIwkk\n" +
	"kvERXtPDqx+W2SpcJ2p1/16bACwG/LNiwwgwHZipK6uclyYl+VuVqLsCAwEAAaAA\n" +
	"MA0GCSqGSIb3DQEBCwUAA4IBAQAXn/JFZc5VJhh6fWg1yivmkBsjI5byanYrsA3f\n" +
	"aA4QC709dw2DFCNYS4q/nMcFhqlskaOeeOcF9KzH1/XTsNmVVkFkEjZy3PRqi2AP\n" +
	"yAx7O1lqjDHDLdEVHUctOfy3MJSu1HtB1J3DNZYgwS4ILC1TJQZU9dSvC1j6PM/R\n" +
	"NxV7PJFEkII/h2WTNNhP73AhcEA4g9PM8c9a0FSwh0yVVVmO5JudGVZ1lFGIKbuU\n" +
	"LQ7RxU9k8vzFAIbB7+tLY2M9fLSvhcnhjvPNrkavqnddtA56nYT5VIuxzdVL94H6\n" +
	"pHW5sFlVYCa0Ytv+OQz5CHWYGz8kNNIOPat7bdEkedfjrRiO\n" +
	"-----END CERTIFICATE REQUEST-----"

// pemLegacyCSRRaw is the same kind of CSR but under the older "NEW CERTIFICATE REQUEST" label
// some tooling (e.g. old OpenSSL) still emits.
const pemLegacyCSRRaw = "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
	"MIICYjCCAUoCAQAwHTEbMBkGA1UEAwwSbGVnYWN5LmV4YW1wbGUuY29tMIIBIjAN\n" +
	"BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlAIRVGkoVx+1L8ivuCOTV/jrZklr\n" +
	"LdbqMzblUqDsQkVjwjTaIibUbEEDNQJHZzCE0IchIfW9dnVkK13/Q7H0gdhjmp2d\n" +
	"JWKqdqFpsaSKC52UIJ3FR3J7feSAnR9LvSi6oHTSMfrwUa7d9CMMwLW7EnJzkrSM\n" +
	"J+SRH49uUT5LfqCaPJTaaBfiqe5ZUQsGdt5136NzGd/BZtl2UsSB3MD/uK8xhzUf\n" +
	"+jS+Mo9tcQENRmLe7RSyUAl8QgbIoq0sTU2i9frIG3TkTzJ1Gor+LkdtdZ9ZKXPk\n" +
	"/KcDsjDMcrGeqQVnhp0qYOvdXNSA0aQR/YLvwfDUDAfgPsHMWXOFN/CIzwIDAQAB\n" +
	"oAAwDQYJKoZIhvcNAQELBQADggEBABI9NF8x7U74+j8kGBhksWox16S3gLS9T0lT\n" +
	"sdo9oxfTFkHXNK4UnU4pBYyDG1+ejwlv9KVPBnmbKbQzbCewM7gTnDupawBg/kTy\n" +
	"QMbNsnYzOIAN3sBld6jNJoMcm16cmjKoTzaS7tVKvif6FVIkmoWY2zrBxCQMlkk6\n" +
	"HYLq5dvH9p9B3RXUhGsW0VlD+qOejHltt43dUMoRxlJP3jYiMW5zpYs5H70wt9iy\n" +
	"iZ4NR9IT8JaI1LPJda48FPda1BAFHf3pyHcw3WE8hgkCPDXJrCmMY4YlknBtGkZQ\n" +
	"WMptMANNDTUEMyP3emgXFYFVWSZX9iHVOpP2KSzSEPg2xldHZ9o=\n" +
	"-----END NEW CERTIFICATE REQUEST-----"

func TestCSRDetectionAndComponent(t *testing.T) {
	detector, err := newDetector()
	if err != nil {
		t.Fatal(err)
	}

	// Filepath deliberately does not end in ".csr" so only the content-based rule fires,
	// keeping this test focused on the "pem-csr" rule itself rather than the path fallback.
	fragment := detect.Fragment{Raw: pemCSRRaw, FilePath: "request.pem"}
	findings := detector.Detect(fragment)
	assert.Len(t, findings, 1)
	assert.Equal(t, "pem-csr", findings[0].RuleID)

	findingWithMeta := findingWithMetadata{
		Finding: findings[0],
		raw:     []byte(pemCSRRaw),
	}
	components, err := findingWithMeta.getComponents()
	if err != nil {
		t.Fatal(err)
	}
	assert.Len(t, components, 1)
	assert.Equal(t, "RSA-2048", components[0].Name)
	assert.Equal(t, cdx.RelatedCryptoMaterialTypePublicKey, components[0].CryptoProperties.RelatedCryptoMaterialProperties.Type)
	assert.Equal(t, "1.2.840.113549.1.1.1", components[0].CryptoProperties.OID)
}

func TestLegacyCSRDetectionAndComponent(t *testing.T) {
	detector, err := newDetector()
	if err != nil {
		t.Fatal(err)
	}

	fragment := detect.Fragment{Raw: pemLegacyCSRRaw, FilePath: "legacy-request.pem"}
	findings := detector.Detect(fragment)
	assert.Len(t, findings, 1)
	assert.Equal(t, "pem-csr", findings[0].RuleID)

	findingWithMeta := findingWithMetadata{
		Finding: findings[0],
		raw:     []byte(pemLegacyCSRRaw),
	}
	components, err := findingWithMeta.getComponents()
	if err != nil {
		t.Fatal(err)
	}
	assert.Len(t, components, 1)
	assert.Equal(t, "RSA-2048", components[0].Name)
}

// A ".csr" file whose content is raw DER (no PEM markers) is only caught by the path-only
// "csr-file" fallback rule; the content regex can't see it, so it should still be reported, as
// a generic secret rather than dropped.
func TestCSRFileFallsBackToGenericSecret(t *testing.T) {
	detector, err := newDetector()
	if err != nil {
		t.Fatal(err)
	}

	rawDER := []byte{0x30, 0x82, 0x02, 0x60, 0x30, 0x82, 0x01, 0x48, 0x02, 0x01, 0x00}

	fragment := detect.Fragment{Raw: string(rawDER), FilePath: "request.csr"}
	findings := detector.Detect(fragment)
	assert.Len(t, findings, 1)
	assert.Equal(t, "csr-file", findings[0].RuleID)

	findingWithMeta := findingWithMetadata{
		Finding: findings[0],
		raw:     rawDER,
	}
	components, err := findingWithMeta.getComponents()
	if err != nil {
		t.Fatal(err)
	}
	assert.Len(t, components, 1)
	assert.Equal(t, "csr-file", components[0].Name)
	assert.Equal(t, cdx.RelatedCryptoMaterialTypeUnknown, components[0].CryptoProperties.RelatedCryptoMaterialProperties.Type)
}

// When a file matches both the "csr-file" path-only fallback rule and its content-based
// counterpart "pem-csr", UpdateBOM must suppress the fallback's redundant generic-secret finding
// and keep only the accurately-parsed one.
func TestUpdateBOMDeduplicatesCSRFileAgainstPEMCSR(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "request.csr"), []byte(pemCSRRaw), 0o600); err != nil {
		t.Fatal(err)
	}

	fs := filesystem.NewPlainFilesystem(dir)
	bom := cdx.NewBOM()
	bom.Components = new([]cdx.Component)

	plugin := &Plugin{}
	if err := plugin.UpdateBOM(fs, bom); err != nil {
		t.Fatal(err)
	}

	assert.Len(t, *bom.Components, 1)
	assert.Equal(t, "RSA-2048", (*bom.Components)[0].Name)
}

// A raw-DER ".csr" file (no PEM markers, so "pem-csr" cannot match) must still be caught by the
// "csr-file" path fallback and reported as a generic secret.
func TestUpdateBOMKeepsCSRFileFallbackWhenContentRuleDoesNotMatch(t *testing.T) {
	dir := t.TempDir()
	rawDER := []byte{0x30, 0x82, 0x02, 0x60, 0x30, 0x82, 0x01, 0x48, 0x02, 0x01, 0x00}
	if err := os.WriteFile(filepath.Join(dir, "request.csr"), rawDER, 0o600); err != nil {
		t.Fatal(err)
	}

	fs := filesystem.NewPlainFilesystem(dir)
	bom := cdx.NewBOM()
	bom.Components = new([]cdx.Component)

	plugin := &Plugin{}
	if err := plugin.UpdateBOM(fs, bom); err != nil {
		t.Fatal(err)
	}

	assert.Len(t, *bom.Components, 1)
	assert.Equal(t, "csr-file", (*bom.Components)[0].Name)
}

// A ".pub" file containing OpenSSH authorized_keys-format content matches both "public-key-file"
// (by extension) and "openssh-public-key" (by content); the fallback's finding must be suppressed.
func TestUpdateBOMDeduplicatesPublicKeyFileAgainstOpenSSHKey(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "id_ed25519.pub"), []byte(opensshEd25519PubRaw), 0o600); err != nil {
		t.Fatal(err)
	}

	fs := filesystem.NewPlainFilesystem(dir)
	bom := cdx.NewBOM()
	bom.Components = new([]cdx.Component)

	plugin := &Plugin{}
	if err := plugin.UpdateBOM(fs, bom); err != nil {
		t.Fatal(err)
	}

	assert.Len(t, *bom.Components, 1)
	assert.Equal(t, "ED25519", (*bom.Components)[0].Name)
}

// A ".pub" file containing a PEM-encoded public key matches both "public-key-file" (by extension)
// and "pem-public-key" (by content); the fallback's finding must be suppressed.
func TestUpdateBOMDeduplicatesPublicKeyFileAgainstPEMPublicKey(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "key.pub"), []byte(pemPublicKeyRaw), 0o600); err != nil {
		t.Fatal(err)
	}

	fs := filesystem.NewPlainFilesystem(dir)
	bom := cdx.NewBOM()
	bom.Components = new([]cdx.Component)

	plugin := &Plugin{}
	if err := plugin.UpdateBOM(fs, bom); err != nil {
		t.Fatal(err)
	}

	assert.Len(t, *bom.Components, 1)
	assert.Equal(t, "RSA-2048", (*bom.Components)[0].Name)
	assert.Equal(t, cdx.RelatedCryptoMaterialTypePublicKey, (*bom.Components)[0].CryptoProperties.RelatedCryptoMaterialProperties.Type)
}

// pemPublicKeyRaw is a standalone PKIX-encoded RSA public key, generated via:
// openssl genrsa 2048 | openssl rsa -pubout
const pemPublicKeyRaw = "-----BEGIN PUBLIC KEY-----\n" +
	"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAprEP7jcBXg/FkuZcCVqU\n" +
	"kusgczZGWo0KaThNckTL+gjc0g8anYpBeHBIZd7YUJ58Uzs8jwK2Qtj4IyZzm7mn\n" +
	"nWEG52mQQMh7H8ssjkR5IojrJ107zCoPPJD84vGuxe0DCPSoKY+lK8OMwUNnJYve\n" +
	"l9yWE/ODGdoWaMzSkuSZM9/WHtapCHV8nYQpDDZXlXjI9d5Ut6r7gLzsDuvt2kT7\n" +
	"A+MgRe5sdsO13vUFJaGLgndUMP3VOXr6/GrSr7vBuErQwuzsBhg131cjHdd+KUZl\n" +
	"KrZqt14o1XiTVcaY1A8diLmuAHKYGGONLpcXjy3X/6DXAzzLPCeGPU9fBM22deEK\n" +
	"BwIDAQAB\n" +
	"-----END PUBLIC KEY-----"

// opensshEd25519PubRaw is an authorized_keys-format OpenSSH public key, generated via:
// ssh-keygen -t ed25519 -N ” -C 'test@example.com' -f id_ed25519
const opensshEd25519PubRaw = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIdKrPosbPQVCc5Nx6qudM+0Hu780M5hFBdf8ZHCkS+8 test@example.com\n"

// opensshRSAPubRaw is an authorized_keys-format OpenSSH RSA public key, generated via:
// ssh-keygen -t rsa -b 2048 -N ” -C 'test@example.com' -f id_rsa
const opensshRSAPubRaw = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC+w3or7inAB1loYIYOsrFnfze2AD9XA/I8owlwCGM3hMwJHpXiEj0opaC2bTZXryHvrHTAwvg6duhWRAmu/YQZ/qgzZN/COkr38pIqdSQ+hNKDXaoO2MUiiDdeO2LONbn9BY4EYB4nCNFr4vqCwLFQFYmXuHbwW1HTMzECn/J8PKXKI+SXFI7k7DHqndsCmvHVRa3sNEs4v9FWymZ9JFm84QpIG60PEAsnkv6VvdIA3VeMFPk7MpvMWDJUXV0KiaYWblS0hOdp1weWSKocoFk6x6dWqMe2HCptUhsbbFp5R8gAr9Y3jaVwyGA9w7LvG4i9iXEfVmIokw69SdU9R6pf test@example.com\n"

func TestOpenSSHPublicKeyDetectionAndComponent(t *testing.T) {
	detector, err := newDetector()
	if err != nil {
		t.Fatal(err)
	}

	fragment := detect.Fragment{Raw: opensshEd25519PubRaw, FilePath: "authorized_keys"}
	findings := detector.Detect(fragment)
	assert.Len(t, findings, 1)
	assert.Equal(t, "openssh-public-key", findings[0].RuleID)

	findingWithMeta := findingWithMetadata{
		Finding: findings[0],
		raw:     []byte(opensshEd25519PubRaw),
	}
	components, err := findingWithMeta.getComponents()
	if err != nil {
		t.Fatal(err)
	}
	assert.Len(t, components, 1)
	assert.Equal(t, "ED25519", components[0].Name)
	assert.Equal(t, cdx.RelatedCryptoMaterialTypePublicKey, components[0].CryptoProperties.RelatedCryptoMaterialProperties.Type)
}

func TestOpenSSHRSAPublicKeyDetectionAndComponent(t *testing.T) {
	detector, err := newDetector()
	if err != nil {
		t.Fatal(err)
	}

	fragment := detect.Fragment{Raw: opensshRSAPubRaw, FilePath: "authorized_keys"}
	findings := detector.Detect(fragment)
	assert.Len(t, findings, 1)
	assert.Equal(t, "openssh-public-key", findings[0].RuleID)

	findingWithMeta := findingWithMetadata{
		Finding: findings[0],
		raw:     []byte(opensshRSAPubRaw),
	}
	components, err := findingWithMeta.getComponents()
	if err != nil {
		t.Fatal(err)
	}
	assert.Len(t, components, 1)
	assert.Equal(t, "RSA-2048", components[0].Name)
}

// ssh2RSAPubRaw is an RFC 4716 ("SSH2 public key", ssh.com/Tectia format) public key, generated via:
// ssh-keygen -t rsa -b 2048 -N ” -f id_rsa_ssh2 && ssh-keygen -e -f id_rsa_ssh2.pub -m RFC4716
const ssh2RSAPubRaw = `---- BEGIN SSH2 PUBLIC KEY ----
Comment: "2048-bit RSA, converted by dubera9@HJKHQC2CRG from OpenSSH"
AAAAB3NzaC1yc2EAAAADAQABAAABAQDOlp3spGE8pvGSbqXLce+htqZMTNjJXu7fQflSWf
SCbaFjXZThTJr2jXcmbCMLfuykq0oPAnPvil19apW+0ubJ8W8H3L3hXcrFwgG0uftoaSof
fOyIO0GfOHLi6aSAgZzPuZsG7QOrzVVwYU+HCrkVERbunn2RmYKoYJ1tD0STkWSZSYsn8F
EstopOmoWyUtyQu1sLBcSsNzHHX/24yp8OPyCrK0J2droEWVHydp+0GQHuoYvWpMzznTve
dyuKdefJ1bXDGqo0TDoVBalriPjpgAL/KxumsyNlcIki3F0zl3pwvb8eZlsEcvk50bpC/8
/k+075dk50mTsnfP7tugyN
---- END SSH2 PUBLIC KEY ----
`

func TestSSH2PublicKeyDetectionAndComponent(t *testing.T) {
	detector, err := newDetector()
	if err != nil {
		t.Fatal(err)
	}

	fragment := detect.Fragment{Raw: ssh2RSAPubRaw, FilePath: "id_rsa_ssh2"}
	findings := detector.Detect(fragment)
	assert.Len(t, findings, 1)
	assert.Equal(t, "ssh2-public-key", findings[0].RuleID)

	findingWithMeta := findingWithMetadata{
		Finding: findings[0],
		raw:     []byte(ssh2RSAPubRaw),
	}
	components, err := findingWithMeta.getComponents()
	if err != nil {
		t.Fatal(err)
	}
	assert.Len(t, components, 1)
	assert.Equal(t, "RSA-2048", components[0].Name)
	assert.Equal(t, cdx.RelatedCryptoMaterialTypePublicKey, components[0].CryptoProperties.RelatedCryptoMaterialProperties.Type)
	assert.NotEmpty(t, components[0].CryptoProperties.RelatedCryptoMaterialProperties.Value)
}

// A ".pub" file containing an RFC 4716 SSH2 public key matches both "public-key-file" (by
// extension) and "ssh2-public-key" (by content); the fallback's finding must be suppressed.
func TestUpdateBOMDeduplicatesPublicKeyFileAgainstSSH2Key(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "id_rsa_ssh2.pub"), []byte(ssh2RSAPubRaw), 0o600); err != nil {
		t.Fatal(err)
	}

	fs := filesystem.NewPlainFilesystem(dir)
	bom := cdx.NewBOM()
	bom.Components = new([]cdx.Component)

	plugin := &Plugin{}
	if err := plugin.UpdateBOM(fs, bom); err != nil {
		t.Fatal(err)
	}

	assert.Len(t, *bom.Components, 1)
	assert.Equal(t, "RSA-2048", (*bom.Components)[0].Name)
}

func TestPEMPublicKeyDetectionAndComponent(t *testing.T) {
	detector, err := newDetector()
	if err != nil {
		t.Fatal(err)
	}

	fragment := detect.Fragment{Raw: pemPublicKeyRaw, FilePath: "key.pem"}
	findings := detector.Detect(fragment)
	assert.Len(t, findings, 1)
	assert.Equal(t, "pem-public-key", findings[0].RuleID)

	findingWithMeta := findingWithMetadata{
		Finding: findings[0],
		raw:     []byte(pemPublicKeyRaw),
	}
	components, err := findingWithMeta.getComponents()
	if err != nil {
		t.Fatal(err)
	}
	assert.Len(t, components, 1)
	assert.Equal(t, "RSA-2048", components[0].Name)
	assert.Equal(t, cdx.RelatedCryptoMaterialTypePublicKey, components[0].CryptoProperties.RelatedCryptoMaterialProperties.Type)
}

// wireguardPublicKeyLineRaw and wireguardPrivateKeyLineRaw are WireGuard config snippets whose
// base64 key material is 32 random bytes - the detection/parsing logic only cares about shape
// (label + 44-char base64 blob), not that the two actually form a matching keypair.
const wireguardPublicKeyLineRaw = "[Peer]\nPublicKey = OknhiyxyaHpbvVkFR+LrzMRkUd0u3sGoM6r+dMsMlWo=\nAllowedIPs = 0.0.0.0/0\n"
const wireguardPrivateKeyLineRaw = "[Interface]\nPrivateKey = /06enBxQ79F2ZoBPze+Dtv4nD5ny+vUHCi9vP5g89Dw=\nAddress = 10.0.0.2/24\n"

func TestWireGuardPublicKeyDetectionAndComponent(t *testing.T) {
	detector, err := newDetector()
	if err != nil {
		t.Fatal(err)
	}

	fragment := detect.Fragment{Raw: wireguardPublicKeyLineRaw, FilePath: "wg0.conf"}
	findings := detector.Detect(fragment)
	assert.Len(t, findings, 1)
	assert.Equal(t, "wireguard-public-key", findings[0].RuleID)

	findingWithMeta := findingWithMetadata{
		Finding: findings[0],
		raw:     []byte(wireguardPublicKeyLineRaw),
	}
	components, err := findingWithMeta.getComponents()
	if err != nil {
		t.Fatal(err)
	}
	assert.Len(t, components, 1)
	assert.Equal(t, "ECDH", components[0].Name)
	assert.Equal(t, cdx.RelatedCryptoMaterialTypePublicKey, components[0].CryptoProperties.RelatedCryptoMaterialProperties.Type)
}

func TestWireGuardPrivateKeyDetectionAndComponent(t *testing.T) {
	detector, err := newDetector()
	if err != nil {
		t.Fatal(err)
	}

	fragment := detect.Fragment{Raw: wireguardPrivateKeyLineRaw, FilePath: "wg0.conf"}
	findings := detector.Detect(fragment)
	assert.Len(t, findings, 1)
	assert.Equal(t, "wireguard-private-key", findings[0].RuleID)

	findingWithMeta := findingWithMetadata{
		Finding: findings[0],
		raw:     []byte(wireguardPrivateKeyLineRaw),
	}
	components, err := findingWithMeta.getComponents()
	if err != nil {
		t.Fatal(err)
	}
	assert.Len(t, components, 1)
	assert.Equal(t, "ECDH", components[0].Name)
	assert.Equal(t, cdx.RelatedCryptoMaterialTypePrivateKey, components[0].CryptoProperties.RelatedCryptoMaterialProperties.Type)
}

// A WireGuard config containing both a "PublicKey" and a "PrivateKey" line (e.g. an [Interface]
// section with its own private key, peered with another endpoint's public key) must be detected
// and reported as two distinct findings/components, not conflated into one.
func TestWireGuardConfigWithBothKeysProducesTwoComponents(t *testing.T) {
	detector, err := newDetector()
	if err != nil {
		t.Fatal(err)
	}

	raw := wireguardPrivateKeyLineRaw + "\n" + wireguardPublicKeyLineRaw
	fragment := detect.Fragment{Raw: raw, FilePath: "wg0.conf"}
	findings := detector.Detect(fragment)
	assert.Len(t, findings, 2)

	ruleIDs := []string{findings[0].RuleID, findings[1].RuleID}
	assert.ElementsMatch(t, []string{"wireguard-public-key", "wireguard-private-key"}, ruleIDs)
}

// pgpPublicKeyRaw is an ASCII-armored OpenPGP public key (primary RSA-2048 sign key plus an
// RSA-2048 encrypt subkey), generated via golang.org/x/crypto/openpgp's own
// openpgp.NewEntity + armor.Encode.
const pgpPublicKeyRaw = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
	"\n" +
	"xsBNBGqoQbEBCACwIjZSAbqi7Kv329mc37lv4Bb1AeilvY/6DPao9BL/M25ZWcvT\n" +
	"Izqc+ay1GAlwhdQMwhwoy7yCTP3FVZRQ65jL2w0K3rcZyH6XUY5NvmiIbLaNgNn4\n" +
	"6TnJ5PZ4J7/POj5+BwmSbPT/v4EJkR88L7TklyXmAdOvHe95/fIjE33hPemRzm7+\n" +
	"naNb6Kvu5W6HcHR2dAjLGt+N27DdJ+LtQYtjRDT9CPVc+SFzX4BMksc1+uppZLZB\n" +
	"yKOZhFPMoZRAWpSnyQ4S0fpNEA3PLTJG5pYG/5gDcGcKYYyc/oMbdQPuEv9Qt7Lo\n" +
	"9H+uRQMuzjkOX3Zq3nClthUuw3OS/hQjDdsFABEBAAHNHFRlc3QgVXNlciA8dGVz\n" +
	"dEBleGFtcGxlLmNvbT7CwGIEEwEIABYFAmqoQbEJEMqBl4T3qWvEAhsDAhkBAAAX\n" +
	"gQgAIM0tKbXnLa2f5GSd7Sx1FC2KJFS/9fJ/dDQgg0NVr9Fgr9NNmVbvL/6cXp6Z\n" +
	"Tz1QB9Z2wgmtzt32iHA49MH4kI3xlaKXAOdGwni9D4vkmTjy67RpWXusgbtGRfPi\n" +
	"P3NIUB74PtGgoc+abFMljV0bTg07RSntO8ReLughwpGaQMOru8eDp0z+iNU8WeFi\n" +
	"wLNVPCJvIzQIrpk1vvvyRpdh5/0yoLRe5EYHXQ9heLOucVQ3HGCxtEpFuUvYgbe0\n" +
	"3Ekv8VXMcv+vZ/cbJJ/NJC5K8nSSZbGV34QC6gICubWSyAM4ryvlhpDZR7fVO89v\n" +
	"KMx71C+RUgo8WjiiOBOotVVS287ATQRqqEGxAQgA3gdZf4FRzLJC1TVewvArLimc\n" +
	"UrndaZilu55VyJU4tGSq0Y46tglud+3s59N0kmR1L9Rg0gUZRafxn3HvHwabHWz9\n" +
	"AfIip5kLDMP9uBEbw9SyKgAYf26yTMSXEzn57P1jwbZUSLkDKH3hlV4OYYBeLsGf\n" +
	"U2SKDk/hhP7sn9kOjO3BJoBzEcu1h1Ze9JnUOhCxQBbwmxtG9kR9zKa8qX6Nq7z7\n" +
	"TE56MsNZeKVoUm4y2ARhcJHbQRTrIVPVpxDmUfJYXKwzHeItHeFSo9mAzYBKTSY7\n" +
	"pP8V1VNO/PcdmmXwj7R61yJVva0xKTuvCcJ70Q0MQyvS/CUG74dx5vYyfdefqQAR\n" +
	"AQABwsBfBBgBCAATBQJqqEGxCRDKgZeE96lrxAIbDAAA0owIADLR9+iQ2THaryC2\n" +
	"+Ty8BwQ+BVPVzBJa6Qy3DKlnpQ4fhqAKDvIxyyYUi2/mZ7894AzJHFz1U3lbHb08\n" +
	"tRJFXIg+jsfQLqo62vGUFviddiLvkw3qKFeR4IQyCNFiiFwJbybC3zAgCAh12aid\n" +
	"CVKWcO74nESrYIjET4EiJqvrn79pgxM5EYiMFgPudsb6UDhLe6OMj3p6WbNQ4GhQ\n" +
	"I0cQCh23CyMnrN0UjPii9aj7NI6bACAu9oqzgEQIQMTS57LdDewcJMzwb9lSjtaO\n" +
	"0NUs4x84vLy+gDwWDEPtcmNUIL83cU5nQLlHeZTYDpltzLMhLw+utPCJTMjRUPJE\n" +
	"tC5iy8M=\n" +
	"=oEXZ\n" +
	"-----END PGP PUBLIC KEY BLOCK-----"

func TestPGPPublicKeyDetectionAndComponent(t *testing.T) {
	detector, err := newDetector()
	if err != nil {
		t.Fatal(err)
	}

	fragment := detect.Fragment{Raw: pgpPublicKeyRaw, FilePath: "pubkey.asc"}
	findings := detector.Detect(fragment)
	assert.Len(t, findings, 1)
	assert.Equal(t, "pgp-public-key", findings[0].RuleID)

	findingWithMeta := findingWithMetadata{
		Finding: findings[0],
		raw:     []byte(pgpPublicKeyRaw),
	}
	components, err := findingWithMeta.getComponents()
	if err != nil {
		t.Fatal(err)
	}
	// Primary RSA sign key plus its RSA encrypt subkey.
	assert.Len(t, components, 2)
	for _, component := range components {
		assert.Equal(t, "RSA-2048", component.Name)
		assert.Equal(t, cdx.RelatedCryptoMaterialTypePublicKey, component.CryptoProperties.RelatedCryptoMaterialProperties.Type)
	}
}

// jwkRSARaw, jwkECRaw and jwkOKPRaw carry real key material generated by Go's crypto/rsa,
// crypto/ecdsa and crypto/ed25519, base64url-encoded per RFC 7517.
const jwkRSARaw = `{"kty":"RSA","n":"xiP4JYCVnQqyYSEODJTY7ibDK0Ec_0eMT9dTo68SerDM0oQWS7tMqR5L4bnPB10sFaKF4iB4-oBiz0SU3YR8m1aciIzEE5q4EVaPdKTTxoI7nh53KTcQGOe--Uy7xwnY5ibZ2S56XbYhrM6LZXEeOqA-IEEu4WjPmheQrtLJfCOAIvcrQCHvb6l5zS_jF4yVuloTv9kYa7E-zd4W7aMyPO_RW_UVYUD84Ej9BBLBdSqlEHPFWz8dTiTd9wWLH_OmT8borNed215CSNJRHV7HQa5Zi3xsoiosRgJLIyqIkobvTHOKgUhAwSGKDmdMWVWJKc6IqC7AMRQbcSusJEcQuQ","e":"AQAB"}`
const jwkECRaw = `{"kty":"EC","crv":"P-256","x":"19m6lp5dI16CVvA1LUQ4nlrchqiAytWhWYorV28u6w8","y":"JDoL31K0OcSnfAUus7GMVnltev88CbOSYeBsdIuQi30"}`
const jwkOKPRaw = `{"kty":"OKP","crv":"Ed25519","x":"gH0BH-IHBC05odjMV1tP0IqqmtPqD8C0cqpiVd7gNSw"}`

func TestJWKRSAPublicKeyDetectionAndComponent(t *testing.T) {
	detector, err := newDetector()
	if err != nil {
		t.Fatal(err)
	}

	fragment := detect.Fragment{Raw: jwkRSARaw, FilePath: "jwks.json"}
	findings := detector.Detect(fragment)
	assert.Len(t, findings, 1)
	assert.Equal(t, "jwk", findings[0].RuleID)

	findingWithMeta := findingWithMetadata{
		Finding: findings[0],
		raw:     []byte(jwkRSARaw),
	}
	components, err := findingWithMeta.getComponents()
	if err != nil {
		t.Fatal(err)
	}
	assert.Len(t, components, 1)
	assert.Equal(t, "RSA-2048", components[0].Name)
	assert.Equal(t, cdx.RelatedCryptoMaterialTypePublicKey, components[0].CryptoProperties.RelatedCryptoMaterialProperties.Type)
}

func TestJWKECPublicKeyDetectionAndComponent(t *testing.T) {
	detector, err := newDetector()
	if err != nil {
		t.Fatal(err)
	}

	fragment := detect.Fragment{Raw: jwkECRaw, FilePath: "jwks.json"}
	findings := detector.Detect(fragment)
	assert.Len(t, findings, 1)
	assert.Equal(t, "jwk", findings[0].RuleID)

	findingWithMeta := findingWithMetadata{
		Finding: findings[0],
		raw:     []byte(jwkECRaw),
	}
	components, err := findingWithMeta.getComponents()
	if err != nil {
		t.Fatal(err)
	}
	assert.Len(t, components, 1)
	assert.Equal(t, "ECDSA", components[0].Name)
}

func TestJWKOKPEd25519PublicKeyDetectionAndComponent(t *testing.T) {
	detector, err := newDetector()
	if err != nil {
		t.Fatal(err)
	}

	fragment := detect.Fragment{Raw: jwkOKPRaw, FilePath: "jwks.json"}
	findings := detector.Detect(fragment)
	assert.Len(t, findings, 1)
	assert.Equal(t, "jwk", findings[0].RuleID)

	findingWithMeta := findingWithMetadata{
		Finding: findings[0],
		raw:     []byte(jwkOKPRaw),
	}
	components, err := findingWithMeta.getComponents()
	if err != nil {
		t.Fatal(err)
	}
	assert.Len(t, components, 1)
	assert.Equal(t, "ED25519", components[0].Name)
}

// A JWK Set ({"keys": [...]}) containing multiple keys must produce one component per key.
func TestJWKSetProducesComponentPerKey(t *testing.T) {
	raw := `{"keys":[` + jwkRSARaw + `,` + jwkECRaw + `]}`

	findingWithMeta := findingWithMetadata{
		Finding: report.Finding{RuleID: "jwk", File: "jwks.json"},
		raw:     []byte(raw),
	}
	components, err := findingWithMeta.getComponents()
	if err != nil {
		t.Fatal(err)
	}
	assert.Len(t, components, 2)
	assert.Equal(t, "RSA-2048", components[0].Name)
	assert.Equal(t, "ECDSA", components[1].Name)
}

// jwkRSAPrivateRaw, jwkECPrivateRaw and jwkOKPPrivateRaw carry real private key material (the
// "d" field, per RFC 7517 sections 6.2/6.3) generated by Go's crypto/rsa, crypto/ecdsa and
// crypto/ed25519, base64url-encoded. A JWK with "d" set describes a private key even though its
// "kty" is the same as the public-key form.
const jwkRSAPrivateRaw = `{"kty":"RSA","n":"r4iJ9wTMaaxT98APjPhH0tV7NZK4es4n8WnP4NyaJ8ctrsByvMX9TXE2ci7NmHWQRG3f3R1ZFoTLQF-Qha63q8w2oqazhoN7qBwLJsOQY_Y0AOkC6HSz369aBzY5lEjAgwEjnN3IcsDve-1uZz2sxoHtsx2SM-vkP9s5obmoCmUesWKpW0OLFyUBWBCi3erw9oKkbEXT3ij1h6xIoztphTdH_gT5pUMMfM89O2nmKtxngFv9j44CFEGH4zfwNwyNSjFBVBECt9FFghT0DTMvOcQXwiJco9WGE1C9mOayNKScLk-d3lMACau5KUdIfTa81ne2v_otC4vP8MpvdYJnsQ","e":"AQAB","d":"BT2XteHlKvH_y0WnCTPH7CveuvObkaIKR_87Wzim2xFrpBwfiNKF7JwYzqmmTnsTELHxlS_JPz59dXls7orP9b958Zr1wOo3xMX6kMCVtOBOvui2AyPp01-wOcclCq_t3HNqIWavM3reY4YsDcXF_OK36qkzOlzccoocYz9QXKgJwH3EFdg-iiDqod-iYNfADZ2cX2HNWmyDaLA4dLkxYa_enj4r17G43tqM_ZWqQ5-BAeeIXKKCl9jH6phnRwUwL-v3swpV9PyH1kRlBCqf80LCY2lVcpKA-vYjR8bXJnr6m6gGgInjGCYJjTpdcQo9k2QX53bFWvTLTmVOcIWUQQ"}`
const jwkECPrivateRaw = `{"kty":"EC","crv":"P-256","x":"ElpVsiOxgmzPFRthGlY1HGlI1XpQZlRU4YM4iGOSmf0","y":"5ZTw4GppjfCZPPYHo195TiXKBjo-CWGqi9-nqdMrhyM","d":"EUKw61L4u4xaZsrE8DhNjxVwHJdxKn_mUMEEaQ84o7A"}`
const jwkOKPEd25519PrivateRaw = `{"kty":"OKP","crv":"Ed25519","x":"yWcCNU05Uz2v3JJJNYGlBKgHoS5kN2ZvB7yELCgR9cA","d":"pHUB60nmiHFmJ_zNc4ZXuEW3UAZ3JXhbCvodA9Ao4Dg"}`

// jwkOctRaw carries a random 256-bit symmetric key, base64url-encoded per RFC 7517 section 6.4.
const jwkOctRaw = `{"kty":"oct","k":"NFmZylvpsXQiZbWQj8jLBUeH-gyOk09rSSXZJUkZxuY"}`

func TestJWKRSAPrivateKeyDetectionAndComponent(t *testing.T) {
	detector, err := newDetector()
	if err != nil {
		t.Fatal(err)
	}

	fragment := detect.Fragment{Raw: jwkRSAPrivateRaw, FilePath: "jwks.json"}
	findings := detector.Detect(fragment)
	assert.Len(t, findings, 1)
	assert.Equal(t, "jwk", findings[0].RuleID)

	findingWithMeta := findingWithMetadata{
		Finding: findings[0],
		raw:     []byte(jwkRSAPrivateRaw),
	}
	components, err := findingWithMeta.getComponents()
	if err != nil {
		t.Fatal(err)
	}
	assert.Len(t, components, 1)
	assert.Equal(t, "RSA-2048", components[0].Name)
	assert.Equal(t, cdx.RelatedCryptoMaterialTypePrivateKey, components[0].CryptoProperties.RelatedCryptoMaterialProperties.Type)
}

func TestJWKECPrivateKeyDetectionAndComponent(t *testing.T) {
	detector, err := newDetector()
	if err != nil {
		t.Fatal(err)
	}

	fragment := detect.Fragment{Raw: jwkECPrivateRaw, FilePath: "jwks.json"}
	findings := detector.Detect(fragment)
	assert.Len(t, findings, 1)
	assert.Equal(t, "jwk", findings[0].RuleID)

	findingWithMeta := findingWithMetadata{
		Finding: findings[0],
		raw:     []byte(jwkECPrivateRaw),
	}
	components, err := findingWithMeta.getComponents()
	if err != nil {
		t.Fatal(err)
	}
	assert.Len(t, components, 1)
	assert.Equal(t, "ECDSA", components[0].Name)
	assert.Equal(t, cdx.RelatedCryptoMaterialTypePrivateKey, components[0].CryptoProperties.RelatedCryptoMaterialProperties.Type)
}

func TestJWKOKPEd25519PrivateKeyDetectionAndComponent(t *testing.T) {
	detector, err := newDetector()
	if err != nil {
		t.Fatal(err)
	}

	fragment := detect.Fragment{Raw: jwkOKPEd25519PrivateRaw, FilePath: "jwks.json"}
	findings := detector.Detect(fragment)
	assert.Len(t, findings, 1)
	assert.Equal(t, "jwk", findings[0].RuleID)

	findingWithMeta := findingWithMetadata{
		Finding: findings[0],
		raw:     []byte(jwkOKPEd25519PrivateRaw),
	}
	components, err := findingWithMeta.getComponents()
	if err != nil {
		t.Fatal(err)
	}
	assert.Len(t, components, 1)
	assert.Equal(t, "ED25519", components[0].Name)
	assert.Equal(t, cdx.RelatedCryptoMaterialTypePrivateKey, components[0].CryptoProperties.RelatedCryptoMaterialProperties.Type)
}

func TestJWKOctSymmetricKeyDetectionAndComponent(t *testing.T) {
	detector, err := newDetector()
	if err != nil {
		t.Fatal(err)
	}

	fragment := detect.Fragment{Raw: jwkOctRaw, FilePath: "jwks.json"}
	findings := detector.Detect(fragment)
	assert.Len(t, findings, 1)
	assert.Equal(t, "jwk", findings[0].RuleID)

	findingWithMeta := findingWithMetadata{
		Finding: findings[0],
		raw:     []byte(jwkOctRaw),
	}
	components, err := findingWithMeta.getComponents()
	if err != nil {
		t.Fatal(err)
	}
	assert.Len(t, components, 1)
	assert.Equal(t, "oct-256", components[0].Name)
	assert.Equal(t, cdx.RelatedCryptoMaterialTypeSecretKey, components[0].CryptoProperties.RelatedCryptoMaterialProperties.Type)
	assert.Equal(t, 256, *components[0].CryptoProperties.RelatedCryptoMaterialProperties.Size)
}

// A JWK Set mixing a public key and a private key must classify each independently.
func TestJWKSetDistinguishesPublicFromPrivateKeys(t *testing.T) {
	raw := `{"keys":[` + jwkRSARaw + `,` + jwkRSAPrivateRaw + `]}`

	findingWithMeta := findingWithMetadata{
		Finding: report.Finding{RuleID: "jwk", File: "jwks.json"},
		raw:     []byte(raw),
	}
	components, err := findingWithMeta.getComponents()
	if err != nil {
		t.Fatal(err)
	}
	assert.Len(t, components, 2)
	assert.Equal(t, cdx.RelatedCryptoMaterialTypePublicKey, components[0].CryptoProperties.RelatedCryptoMaterialProperties.Type)
	assert.Equal(t, cdx.RelatedCryptoMaterialTypePrivateKey, components[1].CryptoProperties.RelatedCryptoMaterialProperties.Type)
}

// A JWK whose key material can't actually be decoded (despite matching the "kty" regex) must
// fall back to a generic secret component classified as key material, not "unknown" - the rule
// id "jwk" doesn't contain the substring "key" that the generic fallback classifier looks for.
func TestJWKUndecodableFallsBackToGenericSecretClassifiedAsKey(t *testing.T) {
	detector, err := newDetector()
	if err != nil {
		t.Fatal(err)
	}

	raw := `{"kty":"RSA","n":"!!!not-base64!!!","e":"AQAB"}`
	fragment := detect.Fragment{Raw: raw, FilePath: "jwks.json"}
	findings := detector.Detect(fragment)
	assert.Len(t, findings, 1)
	assert.Equal(t, "jwk", findings[0].RuleID)

	findingWithMeta := findingWithMetadata{
		Finding: findings[0],
		raw:     []byte(raw),
	}
	components, err := findingWithMeta.getComponents()
	if err != nil {
		t.Fatal(err)
	}
	assert.Len(t, components, 1)
	assert.Equal(t, cdx.RelatedCryptoMaterialTypeKey, components[0].CryptoProperties.RelatedCryptoMaterialProperties.Type)
}

// jwkWithCommonParamsRaw carries the same real RSA-2048 public key material as jwkRSARaw, plus
// RFC 7517 section 4 common parameters: "kid", "use", "key_ops", "alg" and "x5u" (none of which
// have a dedicated CDX field), and "x5t"/"x5t#S256" - real SHA-1/SHA-256 DER thumbprints of the
// self-signed certificate in jwkWithX5cRaw below, generated by Go's crypto/x509.
const jwkWithCommonParamsRaw = `{"kty":"RSA","n":"qCbj2PWZTTwtBz6UvKamUyxOIsYzJX0pdB6G-SxAda3N3KFXG6JZSVxTCr6SV34We3Ehw6wLe-4XWPLIwzisA0egbb2F0gvmv0X7oH4gDj8Lfe4oIBOPDnNrnq9Y0vdUiHggW-TCbXbtBMWh9Q00Ge0uaMFoX5YMv-ViHOYtOK0fNurU0juOj4iN91-1i6NzNvoyZ573PoVgqu062OezkCrGbl7Td10csZxTH4a2J79vQnrJuRTyyKBsMBA8JXZ-bZcpYFWs9Ih_utTWKVi1Aee1saM8DDrJVNv5dgUtXEMN7sGEJCBOmfmRvM52W6i9L3BZltI1-7uwJYsYEpdoIQ","e":"AQAB","kid":"test-kid-1","use":"sig","key_ops":["sign","verify"],"alg":"RS256","x5u":"https://example.com/cert.pem","x5t":"Pd_yKqLpTobQgJcivYCqn0eLfFM","x5t#S256":"__U9rjhpb3csTn4PR-gVZe_sTKkrqaMKqLLtPOfa02M"}`

func TestJWKCommonParamsAnnotateComponent(t *testing.T) {
	detector, err := newDetector()
	if err != nil {
		t.Fatal(err)
	}

	fragment := detect.Fragment{Raw: jwkWithCommonParamsRaw, FilePath: "jwks.json"}
	findings := detector.Detect(fragment)
	assert.Len(t, findings, 1)
	assert.Equal(t, "jwk", findings[0].RuleID)

	findingWithMeta := findingWithMetadata{
		Finding: findings[0],
		raw:     []byte(jwkWithCommonParamsRaw),
	}
	components, err := findingWithMeta.getComponents()
	if err != nil {
		t.Fatal(err)
	}
	assert.Len(t, components, 1)

	related := components[0].CryptoProperties.RelatedCryptoMaterialProperties
	assert.Equal(t, "test-kid-1", related.ID)
	assert.Equal(t, cdx.HashAlgoSHA256, related.Fingerprint.Algorithm)
	assert.Equal(t, "fff53dae38696f772c4e7e0f47e81565efec4ca92ba9a30aa8b2ed3ce7dad363", related.Fingerprint.Value)

	properties := make(map[string]string, len(*components[0].Properties))
	for _, property := range *components[0].Properties {
		properties[property.Name] = property.Value
	}
	assert.Equal(t, "sig", properties["jwk:use"])
	assert.Equal(t, "sign,verify", properties["jwk:key_ops"])
	assert.Equal(t, "RS256", properties["jwk:alg"])
	assert.Equal(t, "https://example.com/cert.pem", properties["jwk:x5u"])
}

// jwkWithX5cRaw carries the same key as jwkWithCommonParamsRaw plus its "x5c" certificate chain:
// a single, real, self-signed RSA certificate (subject/issuer CommonName "jwk-test") generated by
// Go's crypto/x509, base64-encoded (not base64url) per RFC 7517 section 4.7.
const jwkWithX5cRaw = `{"kty":"RSA","n":"qCbj2PWZTTwtBz6UvKamUyxOIsYzJX0pdB6G-SxAda3N3KFXG6JZSVxTCr6SV34We3Ehw6wLe-4XWPLIwzisA0egbb2F0gvmv0X7oH4gDj8Lfe4oIBOPDnNrnq9Y0vdUiHggW-TCbXbtBMWh9Q00Ge0uaMFoX5YMv-ViHOYtOK0fNurU0juOj4iN91-1i6NzNvoyZ573PoVgqu062OezkCrGbl7Td10csZxTH4a2J79vQnrJuRTyyKBsMBA8JXZ-bZcpYFWs9Ih_utTWKVi1Aee1saM8DDrJVNv5dgUtXEMN7sGEJCBOmfmRvM52W6i9L3BZltI1-7uwJYsYEpdoIQ","e":"AQAB","x5c":["MIICnzCCAYegAwIBAgIBATANBgkqhkiG9w0BAQsFADATMREwDwYDVQQDEwhqd2stdGVzdDAeFw0yNjA5MTUxODE4MDJaFw0yNzA5MTUxODE4MDJaMBMxETAPBgNVBAMTCGp3ay10ZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqCbj2PWZTTwtBz6UvKamUyxOIsYzJX0pdB6G+SxAda3N3KFXG6JZSVxTCr6SV34We3Ehw6wLe+4XWPLIwzisA0egbb2F0gvmv0X7oH4gDj8Lfe4oIBOPDnNrnq9Y0vdUiHggW+TCbXbtBMWh9Q00Ge0uaMFoX5YMv+ViHOYtOK0fNurU0juOj4iN91+1i6NzNvoyZ573PoVgqu062OezkCrGbl7Td10csZxTH4a2J79vQnrJuRTyyKBsMBA8JXZ+bZcpYFWs9Ih/utTWKVi1Aee1saM8DDrJVNv5dgUtXEMN7sGEJCBOmfmRvM52W6i9L3BZltI1+7uwJYsYEpdoIQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAHpZgFLEKu/Amj1uDDMKxoLDIPfNirnQM9+bPzo/eFHdWNNKF5+9AcP0TPWvgtjQzFduAnrAbAIKro7cyL77xb5VOTyK2k6/KKCgp0qfViwwxmCe7KR6U2iYTdjU2lwOfMWGCOcrYKFBA9EPixmf6vK8zUbo7BZSkgOQn2/6gR7eZZ3pn16Wp9gMgU/YmaHLKdcSTZGhbamXQ8PifgN8aYjvm9mm68h55njrG1OqMKOQ7xLK1JsugP76KVjCei19iXQM1g9tzadUbXZhccQX4HqYeE9AteBg2kFPna5TJBQSQ2OdXSbr1pMCi5gJ7Yf4Bg/UnZZxO7FQ2tq4Au1VHh"]}`

func TestJWKX5cProducesCertificateComponents(t *testing.T) {
	detector, err := newDetector()
	if err != nil {
		t.Fatal(err)
	}

	fragment := detect.Fragment{Raw: jwkWithX5cRaw, FilePath: "jwks.json"}
	findings := detector.Detect(fragment)
	assert.Len(t, findings, 1)
	assert.Equal(t, "jwk", findings[0].RuleID)

	findingWithMeta := findingWithMetadata{
		Finding: findings[0],
		raw:     []byte(jwkWithX5cRaw),
	}
	components, err := findingWithMeta.getComponents()
	if err != nil {
		t.Fatal(err)
	}
	// The JWK's own RSA-2048 key component, plus the certificate/public-key/algorithm component
	// graph x509.GenerateCdxComponents builds for the one certificate in "x5c".
	assert.Greater(t, len(components), 1)
	assert.Equal(t, "RSA-2048", components[0].Name)

	var certificateComponent *cdx.Component
	for i := range components {
		if components[i].CryptoProperties.AssetType == cdx.CryptoAssetTypeCertificate {
			certificateComponent = &components[i]
			break
		}
	}
	if certificateComponent == nil {
		t.Fatal("expected a certificate component derived from x5c")
	}
	assert.Equal(t, "jwk-test", certificateComponent.CryptoProperties.CertificateProperties.SubjectName)
	assert.Equal(t, "jwk-test", certificateComponent.CryptoProperties.CertificateProperties.IssuerName)
}
