package saml

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
)

func ParseIDPMetadata(metadata []byte) (string, *x509.Certificate, error) {
	s := EntityDescriptor{}
	idPSSOURL := ""
	err := xml.Unmarshal(metadata, &s)
	if err != nil {
		return "", nil, err
	}
	for _, entry := range s.IDPSSODescriptor.SSOService {
		if entry.Binding == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" {
			idPSSOURL = entry.Location
			break
		}
	}
	for _, entry := range s.IDPSSODescriptor.KeyDescriptor {
		if entry.Use == "signing" {
			certstr, err := base64.StdEncoding.DecodeString(entry.KeyInfo.X509Data.X509Certificate.Cert)
			if err != nil {
				return "", nil, err
			}
			cert, err := x509.ParseCertificate([]byte(certstr))
			if err != nil {
				return "", nil, err
			}
			return idPSSOURL, cert, nil
		}
	}
	return idPSSOURL, nil, nil
}
