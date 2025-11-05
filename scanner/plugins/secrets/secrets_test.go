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
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/IBM/cbomkit-theia/provider/cyclonedx"
	"github.com/stretchr/testify/assert"
	"github.com/zricethezav/gitleaks/v8/detect"
	"os"
	"testing"
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
