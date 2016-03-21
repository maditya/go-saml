package saml

import (
	"fmt"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseIDPMetadata(t *testing.T) {
	assert := assert.New(t)
	xmlData, err := ioutil.ReadFile("sample_metadata.xml")
	assert.NoError(err)
	url, cert, err := ParseIDPMetadata(xmlData)
	assert.NoError(err)
	fmt.Println(url)
	fmt.Println(cert)
}
