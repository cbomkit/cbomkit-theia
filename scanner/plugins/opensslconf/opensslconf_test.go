package opensslconf

import (
	"os"
	"strings"
	testing "testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/IBM/cbomkit-theia/provider/filesystem"
	"github.com/stretchr/testify/assert"
)

func Test_parseOpenSSLConf_and_extractRelevantProperties(t *testing.T) {
	content := `
# Comment line
[system_default_sect]
MinProtocol = TLSv1.2
MaxProtocol = TLSv1.3
CipherString = DEFAULT@SECLEVEL=2
Options = ServerPreference,PrioritizeChaCha

[ca_default]
CAfile=/etc/ssl/certs/ca-bundle.crt
CApath=/etc/ssl/certs

[req]
 default_md = sha256
`
	cfg, err := parseOpenSSLConf(strings.NewReader(content))
	assert.NoError(t, err)
	props := extractRelevantProperties(cfg)

	m := map[string]string{}
	for _, p := range props {
		m[p.Name] = p.Value
	}
	assert.Equal(t, "TLSv1.2", m["theia:openssl:MinProtocol"])
	assert.Equal(t, "TLSv1.3", m["theia:openssl:MaxProtocol"])
	assert.Equal(t, "DEFAULT@SECLEVEL=2", m["theia:openssl:CipherString"])
	assert.Equal(t, "ServerPreference,PrioritizeChaCha", m["theia:openssl:Options"])
	assert.Equal(t, "/etc/ssl/certs/ca-bundle.crt", m["theia:openssl:CAfile"])
	assert.Equal(t, "/etc/ssl/certs", m["theia:openssl:CApath"])
	assert.Equal(t, "sha256", m["theia:openssl:default_md"])
}

func Test_UpdateBOM_adds_component(t *testing.T) {
	fs := filesystem.NewPlainFilesystem("../../../testdata/openssl/dir")
	bom := cdx.NewBOM()
	components := make([]cdx.Component, 0)
	bom.Components = &components

	plugin, err := NewOpenSSLConfPlugin()
	assert.NoError(t, err)
	assert.NoError(t, plugin.UpdateBOM(fs, bom))

	assert.NotNil(t, bom.Components)
	assert.GreaterOrEqual(t, len(*bom.Components), 1)

	err = cdx.NewBOMEncoder(os.Stdout, cdx.BOMFileFormatJSON).SetPretty(true).Encode(bom)
	if err != nil {
		t.Fail()
		return
	}

	found := false
	for _, c := range *bom.Components {
		if c.Name == "openssl.cnf" {
			found = true
			assert.NotNil(t, c.Properties)
			props := map[string]string{}
			for _, p := range *c.Properties {
				props[p.Name] = p.Value
			}
			assert.Equal(t, "TLSv1.2", props["theia:openssl:MinProtocol"])
			assert.Equal(t, "TLSv1.3", props["theia:openssl:MaxProtocol"])
			assert.Equal(t, "DEFAULT@SECLEVEL=2", props["theia:openssl:CipherString"])
			assert.Equal(t, "ServerPreference,PrioritizeChaCha", props["theia:openssl:Options"])
			assert.Equal(t, "/etc/ssl/certs/ca-bundle.crt", props["theia:openssl:CAfile"])
			assert.Equal(t, "/etc/ssl/certs", props["theia:openssl:CApath"])
			assert.Equal(t, "sha256", props["theia:openssl:default_md"])
		}
	}
	assert.True(t, found, "openssl.cnf component should be present")
}
