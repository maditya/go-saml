package saml

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"io/ioutil"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRequest(t *testing.T) {
	assert := assert.New(t)

	certPem, err := ioutil.ReadFile("./default.crt")
	assert.NoError(err)
	certBlock, _ := pem.Decode(certPem)
	assert.NotEmpty(certBlock)
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	assert.NoError(err)

	// Construct an AuthnRequest
	authRequest := NewAuthnRequest()
	authRequest.Signature.KeyInfo.X509Data.X509Certificate.Cert = base64.StdEncoding.EncodeToString(cert.Raw)

	b, err := xml.MarshalIndent(authRequest, "", "    ")
	assert.NoError(err)
	xmlAuthnRequest := string(b)

	k, err := ioutil.ReadFile("./default.key")
	assert.NoError(err)
	kd, _ := pem.Decode(k)

	_, err = exec.LookPath("xmlsec1")
	if err != nil {
		t.Skip("skipping subsequent test since xmlsec1 is missing")
	}

	signedXml, err := SignRequest(xmlAuthnRequest, kd.Bytes)
	assert.NoError(err)
	assert.NotEmpty(signedXml)

	err = VerifyRequestSignature(signedXml, cert.Raw)
	assert.NoError(err)
}

func TestResponse(t *testing.T) {
	assert := assert.New(t)

	certPem, err := ioutil.ReadFile("./default.crt")
	assert.NoError(err)
	certBlock, _ := pem.Decode(certPem)
	assert.NotEmpty(certBlock)
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	assert.NoError(err)

	// Construct an AuthnRequest
	response := NewSignedResponse()
	response.Signature.KeyInfo.X509Data.X509Certificate.Cert = base64.StdEncoding.EncodeToString(cert.Raw)

	b, err := xml.MarshalIndent(response, "", "    ")
	assert.NoError(err)
	xmlResponse := string(b)

	k, err := ioutil.ReadFile("./default.key")
	assert.NoError(err)
	kd, _ := pem.Decode(k)

	_, err = exec.LookPath("xmlsec1")
	if err != nil {
		t.Skip("skipping subsequent test since xmlsec1 is missing")
	}

	signedXml, err := SignResponse(xmlResponse, kd.Bytes)
	assert.NoError(err)
	assert.NotEmpty(signedXml)

	err = VerifyRequestSignature(signedXml, cert.Raw)
	assert.NoError(err)
}
