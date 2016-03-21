package saml

import (
	"crypto"
	"crypto/x509"
	"encoding/xml"
)

// ServiceProviderConfig provides settings to configure server acting as a SAML Service Provider.
// Expect only one IDP per SP in this configuration. If you need to configure multipe IDPs for an SP
// then configure multiple instances of this module
type ServiceProviderConfig struct {
	PrivateKey                  crypto.PrivateKey
	Cert                        *x509.Certificate
	IDPSSOURL                   string
	IDPSSODescriptorURL         string
	IDPCert                     *x509.Certificate
	AssertionConsumerServiceURL string
	SPSignRequest               bool
}

type IdentityProviderSettings struct {
}

type Assertion struct {
	XMLName            xml.Name
	ID                 string `xml:"ID,attr"`
	Version            string `xml:"Version,attr"`
	XS                 string `xml:"xmlns:xs,attr"`
	XSI                string `xml:"xmlns:xsi,attr"`
	SAML               string `xml:"saml,attr"`
	IssueInstant       string `xml:"IssueInstant,attr"`
	Issuer             Issuer `xml:"Issuer"`
	Subject            Subject
	Conditions         Conditions
	AttributeStatement AttributeStatement
}

type AssertionConsumerService struct {
	XMLName  xml.Name
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
	Index    string `xml:"index,attr"`
}

type AuthnContextClassRef struct {
	XMLName   xml.Name
	SAML      string `xml:"xmlns:saml,attr"`
	Transport string `xml:",innerxml"`
}

type AuthnRequest struct {
	XMLName                        xml.Name
	SAMLP                          string                `xml:"xmlns:samlp,attr"`
	SAML                           string                `xml:"xmlns:saml,attr"`
	SAMLSIG                        string                `xml:"xmlns:samlsig,attr"`
	ID                             string                `xml:"ID,attr"`
	Version                        string                `xml:"Version,attr"`
	ProtocolBinding                string                `xml:"ProtocolBinding,attr"`
	AssertionConsumerServiceURL    string                `xml:"AssertionConsumerServiceURL,attr"`
	Destination                    string                `xml:"Destination,attr"`
	ForceAuthn                     string                `xml:"ForceAuthn,attr,omitempty"`
	IssueInstant                   string                `xml:"IssueInstant,attr"`
	AssertionConsumerServiceIndex  int                   `xml:"AssertionConsumerServiceIndex,attr"`
	AttributeConsumingServiceIndex int                   `xml:"AttributeConsumingServiceIndex,attr"`
	Issuer                         Issuer                `xml:"Issuer"`
	NameIDPolicy                   NameIDPolicy          `xml:"NameIDPolicy"`
	RequestedAuthnContext          RequestedAuthnContext `xml:"RequestedAuthnContext"`
	Signature                      Signature             `xml:"Signature,omitempty"`
	originalString                 string
}

type Attribute struct {
	XMLName        xml.Name
	Name           string `xml:",attr"`
	FriendlyName   string `xml:",attr"`
	NameFormat     string `xml:",attr"`
	AttributeValue AttributeValue
}

type AttributeStatement struct {
	XMLName    xml.Name
	Attributes []Attribute `xml:"Attribute"`
}

type AttributeValue struct {
	XMLName xml.Name
	Type    string `xml:"xsi:type,attr"`
	Value   string `xml:",innerxml"`
}

type CanonicalizationMethod struct {
	XMLName   xml.Name
	Algorithm string `xml:"Algorithm,attr"`
}

type Conditions struct {
	XMLName      xml.Name
	NotBefore    string `xml:",attr"`
	NotOnOrAfter string `xml:",attr"`
}

type DigestMethod struct {
	XMLName   xml.Name
	Algorithm string `xml:"Algorithm,attr"`
}

type DigestValue struct {
	XMLName xml.Name
}

type EntityAttributes struct {
	XMLName          xml.Name
	SAML             string      `xml:"xmlns:saml,attr"`
	EntityAttributes []Attribute `xml:"Attribute"` // should be array??
}

type EntityDescriptor struct {
	XMLName  xml.Name
	DS       string `xml:"xmlns:ds,attr"`
	XMLNS    string `xml:"xmlns,attr"`
	MD       string `xml:"xmlns:md,attr"`
	EntityId string `xml:"entityID,attr"`

	Extensions       Extensions       `xml:"Extensions"`
	IDPSSODescriptor IDPSSODescriptor `xml:"IDPSSODescriptor"`
	SPSSODescriptor  SPSSODescriptor  `xml:"SPSSODescriptor"`
}

type Extensions struct {
	XMLName xml.Name
	Alg     string `xml:"xmlns:alg,attr"`
	MDAttr  string `xml:"xmlns:mdattr,attr"`
	MDRPI   string `xml:"xmlns:mdrpi,attr"`

	EntityAttributes string `xml:"EntityAttributes"`
}

type IDPSSODescriptor struct {
	XMLName       xml.Name
	SSOService    []SSOService    `xml:"SingleSignOnService"`
	KeyDescriptor []KeyDescriptor `xml:"KeyDescriptor"`
}

type Issuer struct {
	XMLName xml.Name
	SAML    string `xml:"xmlns:saml,attr,omitempty"`
	Url     string `xml:",innerxml"`
}

type KeyDescriptor struct {
	XMLName xml.Name
	KeyInfo KeyInfo `xml:"KeyInfo"`
	Use     string  `xml:"use,attr"`
}

type KeyInfo struct {
	XMLName  xml.Name
	X509Data X509Data `xml:"X509Data"`
}

type NameID struct {
	XMLName xml.Name
	Format  string `xml:",attr"`
	Value   string `xml:",innerxml"`
}

type NameIDPolicy struct {
	XMLName     xml.Name
	AllowCreate bool   `xml:"AllowCreate,attr"`
	Format      string `xml:"Format,attr"`
}

type Response struct {
	XMLName      xml.Name
	SAMLP        string `xml:"xmlns:samlp,attr"`
	SAML         string `xml:"xmlns:saml,attr"`
	SAMLSIG      string `xml:"xmlns:samlsig,attr"`
	Destination  string `xml:"Destination,attr"`
	ID           string `xml:"ID,attr"`
	Version      string `xml:"Version,attr"`
	IssueInstant string `xml:"IssueInstant,attr"`
	InResponseTo string `xml:"InResponseTo,attr"`

	Assertion Assertion `xml:"Assertion"`
	Signature Signature `xml:"Signature"`
	Issuer    Issuer    `xml:"Issuer"`
	Status    Status    `xml:"Status"`

	originalString string
}

type RequestedAuthnContext struct {
	XMLName              xml.Name
	SAMLP                string               `xml:"xmlns:samlp,attr"`
	Comparison           string               `xml:"Comparison,attr"`
	AuthnContextClassRef AuthnContextClassRef `xml:"AuthnContextClassRef"`
}

type SamlsigReference struct {
	XMLName      xml.Name
	URI          string       `xml:"URI,attr"`
	Transforms   Transforms   `xml:",innerxml"`
	DigestMethod DigestMethod `xml:",innerxml"`
	DigestValue  DigestValue  `xml:",innerxml"`
}

type Signature struct {
	XMLName        xml.Name
	Id             string `xml:"Id,attr"`
	SignedInfo     SignedInfo
	SignatureValue SignatureValue
	KeyInfo        KeyInfo
}

type SignatureMethod struct {
	XMLName   xml.Name
	Algorithm string `xml:"Algorithm,attr"`
}

type SignatureValue struct {
	XMLName xml.Name
	Value   string `xml:",innerxml"`
}

type SignedInfo struct {
	XMLName                xml.Name
	CanonicalizationMethod CanonicalizationMethod
	SignatureMethod        SignatureMethod
	SamlsigReference       SamlsigReference
}

type SPSSODescriptor struct {
	XMLName                    xml.Name
	ProtocolSupportEnumeration string `xml:"protocolSupportEnumeration,attr"`
	SigningKeyDescriptor       KeyDescriptor
	EncryptionKeyDescriptor    KeyDescriptor
	// SingleLogoutService        SingleLogoutService `xml:"SingleLogoutService"`
	AssertionConsumerServices []AssertionConsumerService
}

type SPSSODescriptors struct {
}

type SSOService struct {
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
}

type SingleLogoutService struct {
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
}

type Status struct {
	XMLName    xml.Name
	StatusCode StatusCode `xml:"StatusCode"`
}

type StatusCode struct {
	XMLName xml.Name
	Value   string `xml:",attr"`
}

type Subject struct {
	XMLName             xml.Name
	NameID              NameID
	SubjectConfirmation SubjectConfirmation
}

type SubjectConfirmation struct {
	XMLName                 xml.Name
	Method                  string `xml:",attr"`
	SubjectConfirmationData SubjectConfirmationData
}

type SubjectConfirmationData struct {
	InResponseTo string `xml:",attr"`
	NotOnOrAfter string `xml:",attr"`
	Recipient    string `xml:",attr"`
}

type Transform struct {
	XMLName   xml.Name
	Algorithm string `xml:"Algorithm,attr"`
}

type Transforms struct {
	XMLName   xml.Name
	Transform Transform
}

type X509Certificate struct {
	XMLName xml.Name
	Cert    string `xml:",innerxml"`
}

type X509Data struct {
	XMLName         xml.Name
	X509Certificate X509Certificate `xml:"X509Certificate"`
}
