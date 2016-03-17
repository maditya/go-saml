package saml

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetSignedRequest(t *testing.T) {
	assert := assert.New(t)
	privateKey, err := ioutil.ReadFile("./default.key")
	assert.NoError(err)
	certPem, err := ioutil.ReadFile("./default.crt")
	assert.NoError(err)
	certBlock, _ := pem.Decode(certPem)
	assert.NotEmpty(certBlock)
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	assert.NoError(err)
	sp := ServiceProviderConfig{
		PrivateKey:                  privateKey,
		Cert:                        cert,
		IDPSSOURL:                   "http://www.onelogin.net",
		IDPSSODescriptorURL:         "http://www.onelogin.net",
		IDPCert:                     cert,
		AssertionConsumerServiceURL: "http://localhost:8000/auth/saml/name",
		SPSignRequest:               true,
	}

	// Construct an AuthnRequest
	authnRequest := sp.GetAuthnRequest()
	signedXML, err := authnRequest.SignedString(sp.PrivateKey)
	assert.NoError(err)
	assert.NotEmpty(signedXML)

	err = VerifyRequestSignature(signedXML, sp.Cert.Raw)
	assert.NoError(err)
}

func TestGetUnsignedRequest(t *testing.T) {
	assert := assert.New(t)
	certPem, err := ioutil.ReadFile("./default.crt")
	assert.NoError(err)
	certBlock, _ := pem.Decode(certPem)
	assert.NotEmpty(certBlock)
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	assert.NoError(err)
	sp := ServiceProviderConfig{
		Cert:                        cert,
		IDPSSOURL:                   "http://www.onelogin.net",
		IDPSSODescriptorURL:         "http://www.onelogin.net",
		IDPCert:                     cert,
		AssertionConsumerServiceURL: "http://localhost:8000/auth/saml/name",
		SPSignRequest:               false,
	}

	// Construct an AuthnRequest
	authnRequest := sp.GetAuthnRequest()
	assert.NoError(err)
	assert.NotEmpty(authnRequest)
}
