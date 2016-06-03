package saml

import (
	"errors"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
)

const (
	xmlResponseID = "urn:oasis:names:tc:SAML:2.0:protocol:Response"
	xmlRequestID  = "urn:oasis:names:tc:SAML:2.0:protocol:AuthnRequest"
)

// SignRequest signs a SAML 2.0 AuthnRequest
// xmlsec1 is run out of process through `exec`
func SignRequest(xml string, privateKey []byte) (string, error) {
	return sign(xml, privateKey, xmlRequestID)
}

// SignResponse signs a SAML 2.0 Response
// xmlsec1 is run out of process through `exec`
func SignResponse(xml string, privateKey []byte) (string, error) {
	return sign(xml, privateKey, xmlResponseID)
}

func sign(xml string, privateKey []byte, id string) (string, error) {

	samlXmlsecInput, err := ioutil.TempFile(os.TempDir(), "tmpgs")
	if err != nil {
		return "", err
	}
	defer deleteTempFile(samlXmlsecInput.Name())
	samlXmlsecInput.WriteString("<?xml version='1.0' encoding='UTF-8'?>\n")
	samlXmlsecInput.WriteString(xml)
	samlXmlsecInput.Close()

	samlXmlsecOutput, err := ioutil.TempFile(os.TempDir(), "tmpgs")
	if err != nil {
		return "", err
	}
	defer deleteTempFile(samlXmlsecOutput.Name())
	samlXmlsecOutput.Close()

	privKeyFile, err := ioutil.TempFile(os.TempDir(), "tmpgs")
	if err != nil {
		return "", err
	}
	defer deleteTempFile(privKeyFile.Name())
	ioutil.WriteFile(privKeyFile.Name(), privateKey, 0644)

	//fmt.Println("xmlsec1", "--sign", "--privkey-der", privateKeyFile.Name(),
	//	"--id-attr:ID", id,
	//	"--output", samlXmlsecOutput.Name(), samlXmlsecInput.Name())
	output, err := exec.Command("xmlsec1", "--sign", "--privkey-der", privKeyFile.Name(),
		"--id-attr:ID", id,
		"--output", samlXmlsecOutput.Name(), samlXmlsecInput.Name()).CombinedOutput()
	if err != nil {
		return "", errors.New(err.Error() + " : " + string(output))
	}

	samlSignedRequest, err := ioutil.ReadFile(samlXmlsecOutput.Name())
	if err != nil {
		return "", err
	}
	samlSignedRequestXML := strings.Trim(string(samlSignedRequest), "\n")
	return samlSignedRequestXML, nil
}

// VerifyResponseSignature verify signature of a SAML 2.0 Response document
// xmlsec1 is run out of process through `exec`
func VerifyResponseSignature(xml string, cert []byte) error {
	return verify(xml, cert, xmlResponseID)
}

// VerifyRequestSignature verify signature of a SAML 2.0 AuthnRequest document
// xmlsec1 is run out of process through `exec`
func VerifyRequestSignature(xml string, cert []byte) error {
	return verify(xml, cert, xmlRequestID)
}

func verify(xml string, cert []byte, id string) error {
	// Write saml to
	samlXmlsecInput, err := ioutil.TempFile(os.TempDir(), "tmpgs")
	if err != nil {
		return err
	}

	samlXmlsecInput.WriteString(xml)
	samlXmlsecInput.Close()
	defer deleteTempFile(samlXmlsecInput.Name())

	certFile, err := ioutil.TempFile(os.TempDir(), "tmpgs")
	if err != nil {
		return err
	}
	defer deleteTempFile(certFile.Name())
	ioutil.WriteFile(certFile.Name(), cert, 0644)

	_, err = exec.Command("xmlsec1", "--verify", "--pubkey-cert-der", certFile.Name(), "--id-attr:ID", id, samlXmlsecInput.Name()).CombinedOutput()
	if err != nil {
		return errors.New("error verifying signature: " + err.Error())
	}
	return nil
}

// deleteTempFile removes the specified file and ignores error
// Intended to be called in a defer after the creation of a temp file to ensure cleanup
func deleteTempFile(filename string) {
	_ = os.Remove(filename)
}
