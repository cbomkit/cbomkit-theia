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

package key

import (
	"crypto/dsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Unlike RSA/ECDSA/ED25519/ECDH, crypto/x509.MarshalPKIXPublicKey does not support DSA, so
// getDSAPublicKeyComponent hand-builds the SubjectPublicKeyInfo DER itself. This verifies that
// encoding round-trips through crypto/x509.ParsePKIXPublicKey (which does support parsing DSA)
// back to the original P/Q/G/Y.
func TestDSAPublicKeyComponentIncludesKeyValue(t *testing.T) {
	var params dsa.Parameters
	if err := dsa.GenerateParameters(&params, rand.Reader, dsa.L1024N160); err != nil {
		t.Fatal(err)
	}
	var priv dsa.PrivateKey
	priv.Parameters = params
	if err := dsa.GenerateKey(&priv, rand.Reader); err != nil {
		t.Fatal(err)
	}

	component, err := GenerateCdxComponent(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	related := component.CryptoProperties.RelatedCryptoMaterialProperties
	assert.NotEmpty(t, related.Value)

	der, err := base64.StdEncoding.DecodeString(related.Value)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatal(err)
	}
	dsaKey, ok := parsed.(*dsa.PublicKey)
	if !ok {
		t.Fatalf("parsed key is %T, not *dsa.PublicKey", parsed)
	}
	assert.Zero(t, dsaKey.P.Cmp(priv.PublicKey.P))
	assert.Zero(t, dsaKey.Q.Cmp(priv.PublicKey.Q))
	assert.Zero(t, dsaKey.G.Cmp(priv.PublicKey.G))
	assert.Zero(t, dsaKey.Y.Cmp(priv.PublicKey.Y))
}

func TestDSAPrivateKeyComponent(t *testing.T) {
	var params dsa.Parameters
	if err := dsa.GenerateParameters(&params, rand.Reader, dsa.L1024N160); err != nil {
		t.Fatal(err)
	}
	var priv dsa.PrivateKey
	priv.Parameters = params
	if err := dsa.GenerateKey(&priv, rand.Reader); err != nil {
		t.Fatal(err)
	}

	component, err := GenerateCdxComponent(&priv)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "DSA", component.Name)
	related := component.CryptoProperties.RelatedCryptoMaterialProperties
	assert.NotNil(t, related.Size)
	assert.Equal(t, priv.PublicKey.Y.BitLen(), *related.Size)
}
