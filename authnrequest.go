// Copyright 2014 Matthew Baird, Andrew Mussey
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

package saml

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/maditya/go-saml/util"
)

func ParseCompressedEncodedRequest(b64RequestXML string) (*AuthnRequest, error) {
	var authnRequest AuthnRequest
	compressedXML, err := base64.StdEncoding.DecodeString(b64RequestXML)
	if err != nil {
		return nil, err
	}
	bXML := util.Decompress(compressedXML)

	err = xml.Unmarshal(bXML, &authnRequest)
	if err != nil {
		return nil, err
	}

	// There is a bug with XML namespaces in Go that's causing XML attributes with colons to not be roundtrip
	// marshal and unmarshaled so we'll keep the original string around for validation.
	authnRequest.originalString = string(bXML)
	return &authnRequest, nil

}

func ParseEncodedRequest(b64RequestXML string) (*AuthnRequest, error) {
	authnRequest := AuthnRequest{}
	bytesXML, err := base64.StdEncoding.DecodeString(b64RequestXML)
	if err != nil {
		return nil, err
	}
	err = xml.Unmarshal(bytesXML, &authnRequest)
	if err != nil {
		return nil, err
	}

	// There is a bug with XML namespaces in Go that's causing XML attributes with colons to not be roundtrip
	// marshal and unmarshaled so we'll keep the original string around for validation.
	authnRequest.originalString = string(bytesXML)
	return &authnRequest, nil
}

func (r *AuthnRequest) Validate(cert []byte) error {
	if r.Version != "2.0" {
		return errors.New("unsupported SAML Version")
	}

	if len(r.ID) == 0 {
		return errors.New("missing ID attribute on SAML Response")
	}

	// TODO more validation

	err := VerifyRequestSignature(r.originalString, cert)
	if err != nil {
		return err
	}

	return nil
}

// GetSignedAuthnRequest returns a singed XML document that represents a AuthnRequest SAML document
func (s *ServiceProviderConfig) GetAuthnRequest() (*AuthnRequest, error) {
	if s.Cert == nil {
		return nil, fmt.Errorf("saml:GetAuthnRequest:invalid cert provided")
	}
	r := NewAuthnRequest()
	r.AssertionConsumerServiceURL = s.AssertionConsumerServiceURL
	r.Issuer.Url = s.AssertionConsumerServiceURL
	r.Destination = s.IDPSSOURL
	r.Signature.KeyInfo.X509Data.X509Certificate.Cert = base64.StdEncoding.EncodeToString(s.Cert.Raw)

	return r, nil
}

// GetAuthnRequestURL generate a URL for the AuthnRequest to the IdP with the SAMLRequst parameter encoded
func GetAuthnRequestURL(baseURL string, b64XML string, state string) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	q := u.Query()
	q.Add("SAMLRequest", b64XML)
	q.Add("RelayState", state)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func NewAuthnRequest() *AuthnRequest {
	id := util.ID()
	return &AuthnRequest{
		XMLName: xml.Name{
			Local: "saml2p:AuthnRequest",
		},
		SAMLP:                       "urn:oasis:names:tc:SAML:2.0:protocol",
		SAML:                        "urn:oasis:names:tc:SAML:2.0:assertion",
		SAMLSIG:                     "http://www.w3.org/2000/09/xmldsig#",
		ID:                          id,
		ProtocolBinding:             "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
		Version:                     "2.0",
		ForceAuthn:                  "false",
		AssertionConsumerServiceURL: "", // caller must populate ar.AppSettings.AssertionConsumerServiceURL,
		Issuer: Issuer{
			XMLName: xml.Name{
				Local: "saml2:Issuer",
			},
			Url:  "", // caller must populate ar.AppSettings.Issuer
			SAML: "urn:oasis:names:tc:SAML:2.0:assertion",
		},
		IssueInstant: time.Now().UTC().Format(time.RFC3339Nano),
		NameIDPolicy: NameIDPolicy{
			XMLName: xml.Name{
				Local: "saml2p:NameIDPolicy",
			},
			AllowCreate: true,
			Format:      "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
		},
		RequestedAuthnContext: RequestedAuthnContext{
			XMLName: xml.Name{
				Local: "saml2p:RequestedAuthnContext",
			},
			SAMLP:      "urn:oasis:names:tc:SAML:2.0:protocol",
			Comparison: "exact",
			AuthnContextClassRef: AuthnContextClassRef{
				XMLName: xml.Name{
					Local: "saml:AuthnContextClassRef",
				},
				SAML:      "urn:oasis:names:tc:SAML:2.0:assertion",
				Transport: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
			},
		},
		Signature: Signature{
			XMLName: xml.Name{
				Local: "samlsig:Signature",
			},
			Id: "Signature1",
			SignedInfo: SignedInfo{
				XMLName: xml.Name{
					Local: "samlsig:SignedInfo",
				},
				CanonicalizationMethod: CanonicalizationMethod{
					XMLName: xml.Name{
						Local: "samlsig:CanonicalizationMethod",
					},
					Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
				},
				SignatureMethod: SignatureMethod{
					XMLName: xml.Name{
						Local: "samlsig:SignatureMethod",
					},
					Algorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
				},
				SamlsigReference: SamlsigReference{
					XMLName: xml.Name{
						Local: "samlsig:Reference",
					},
					URI: "#" + id,
					Transforms: Transforms{
						XMLName: xml.Name{
							Local: "samlsig:Transforms",
						},
						Transform: Transform{
							XMLName: xml.Name{
								Local: "samlsig:Transform",
							},
							Algorithm: "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
						},
					},
					DigestMethod: DigestMethod{
						XMLName: xml.Name{
							Local: "samlsig:DigestMethod",
						},
						Algorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
					},
					DigestValue: DigestValue{
						XMLName: xml.Name{
							Local: "samlsig:DigestValue",
						},
					},
				},
			},
			SignatureValue: SignatureValue{
				XMLName: xml.Name{
					Local: "samlsig:SignatureValue",
				},
			},
			KeyInfo: KeyInfo{
				XMLName: xml.Name{
					Local: "samlsig:KeyInfo",
				},
				X509Data: X509Data{
					XMLName: xml.Name{
						Local: "samlsig:X509Data",
					},
					X509Certificate: X509Certificate{
						XMLName: xml.Name{
							Local: "samlsig:X509Certificate",
						},
						Cert: "", // caller must populate cert,
					},
				},
			},
		},
	}
}

func (r *AuthnRequest) String() (string, error) {
	b, err := xml.MarshalIndent(r, "", "    ")
	if err != nil {
		return "", err
	}

	return string(b), nil
}

func (r *AuthnRequest) SignedString(privateKey crypto.PrivateKey) (string, error) {
	s, err := r.String()
	if err != nil {
		return "", err
	}
	if privateKey == nil {
		return "", fmt.Errorf("saml:SignedString:private key cannot be nil")
	}
	key, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("saml:SignedString:private key type not supported")
	}
	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	return SignRequest(s, keyBytes)
}

// GetAuthnRequestURL generate a URL for the AuthnRequest to the IdP with the SAMLRequst parameter encoded
func (r *AuthnRequest) EncodedSignedString(privateKey crypto.PrivateKey) (string, error) {
	signed, err := r.SignedString(privateKey)
	if err != nil {
		return "", err
	}
	b64XML := base64.StdEncoding.EncodeToString([]byte(signed))
	return b64XML, nil
}

func (r *AuthnRequest) CompressedEncodedSignedString(privateKey crypto.PrivateKey) (string, error) {
	signed, err := r.SignedString(privateKey)
	if err != nil {
		return "", err
	}
	compressed := util.Compress([]byte(signed))
	b64XML := base64.StdEncoding.EncodeToString(compressed)
	return b64XML, nil
}

func (r *AuthnRequest) EncodedString() (string, error) {
	saml, err := r.String()
	if err != nil {
		return "", err
	}
	b64XML := base64.StdEncoding.EncodeToString([]byte(saml))
	return b64XML, nil
}

func (r *AuthnRequest) CompressedEncodedString() (string, error) {
	saml, err := r.String()
	if err != nil {
		return "", err
	}
	compressed := util.Compress([]byte(saml))
	b64XML := base64.StdEncoding.EncodeToString(compressed)
	return b64XML, nil
}
