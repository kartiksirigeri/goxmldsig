package dsig

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io/ioutil"
	"testing"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/require"
)

func TestSign_RSAKeyValue(t *testing.T)  {
	tryout := `
<bbps:BillFetchRequest xmlns:bbps="http://bbps.org/schema">
   <Head ver="1.0" ts="2019-02-16T22:02:36+05:30" origInst="BBCU" refId="HENSVVR4QOS7X1UGPY7JGUV444PL9T2C3QM"/>
   <Analytics>
      <Tag name="FETCHREQUESTSTART" value="2019-02-16T22:02:00+05:30"/>
      <Tag name="FETCHREQUESTEND" value="2019-02-16T22:02:35+05:30"/>
   </Analytics>
   <Txn ts="2019-02-16T22:02:35+05:30" msgId="8ENSVVR4QOS7X1UGPY7JGUV444PL9T2C3QX">
      <RiskScores>
         <Score provider="OU01" type="TXNRISK" value="030"/>
         <Score provider="BBPS" type="TXNRISK" value="030"/>
      </RiskScores>
   </Txn>
   <Customer mobile="9505XXXX98">
      <Tag name="EMAIL" value="manoj.chekuri@npci.org.in"/>
      <Tag name="AADHAAR" value="123456789012"/>
      <Tag name="PAN" value="BXXCG7754K"/>
   </Customer>
   <Agent id="OU01XXXXINT001123456">
      <Device>
         <Tag name="MOBILE" value="9830098300"/>
         <Tag name="GEOCODE" value="12.9667,77.5667"/>
         <Tag name="POSTAL_CODE" value="400063"/>
         <Tag name="IP" value="124.170.23.22"/>
         <Tag name="INITIATING_CHANNEL" value="INT/INTB/MOB/MOBB/KIOSK/ATM/BNKBRNCH/AGT/BSC"/>
         <Tag name="TERMINAL_ID" value="1234556"/>
         <Tag name="IMEI" value="123456789012345"/>
         <Tag name="IFSC" value="ABCD0001234"/>
         <Tag name="MAC" value="00-0D-60-07-2A-FO"/>
         <Tag name="OS" value="iOS"/>
         <Tag name="APP" value="AGENTAPP"/>
      </Device>
   </Agent>
   <BillDetails>
      <Biller id="VODA00000MUM03"/>
      <CustomerParams>
         <Tag name="RefFld1" value=""/>
         <Tag name="RefFld2" value=""/>
         <Tag name="RefFld3" value=""/>
      </CustomerParams>
   </BillDetails>
</bbps:BillFetchRequest>`

	doc := etree.NewDocument()
	err := doc.ReadFromBytes([]byte(tryout))

	pkeyBytes, err := ioutil.ReadFile("test_privatekey")
	if err != nil {
		panic(err)
	}

	certBytes, err := ioutil.ReadFile("test_certificate.cer")
	_, err = x509.ParseCertificate(certBytes)
	if err != nil {
		panic(err)
	}

	p, _ := pem.Decode(pkeyBytes)
	privateKey, err := x509.ParsePKCS1PrivateKey(p.Bytes)
	if err != nil {
		panic(err)
	}


	storeForTest := &MemoryX509KeyStore{}
	storeForTest.SetKeyPair(privateKey, certBytes)
	ctx := NewDefaultSigningContext(storeForTest)
	ctx.Prefix = ""
	ctx.KeyInfoType = RSAKeyInfo
	signedElement, err := ctx.SignEnveloped(doc.Root())
	require.NoError(t, err)

	element := signedElement.FindElement("//Signature/SignatureValue")
	require.NotEmpty(t, element)

	element = signedElement.FindElement("//Signature/KeyInfo/KeyValue/RSAKeyValue/Modulus")
	require.NotEmpty(t, element)

	element = signedElement.FindElement("//Signature/KeyInfo/KeyValue/RSAKeyValue/Exponent")
	require.NotEmpty(t, element)

	//doc = etree.NewDocument()
	//doc.SetRoot(signedElement)
	//signedXml, err := doc.WriteToString()
	//if err != nil {
	//	panic(err)
	//}

	//ioutil.WriteFile("C:/Users/sirigeri/Desktop/signed_xml.txt", []byte(signedXml), 777)
	//
	//signedBytes, err := ioutil.ReadFile("C:/Users/sirigeri/Desktop/signed_xml.txt")
	//if err != nil {
	//	panic(err)
	//}

}

func TestSign(t *testing.T) {
	randomKeyStore := RandomKeyStoreForTest()
	ctx := NewDefaultSigningContext(randomKeyStore)

	authnRequest := &etree.Element{
		Space: "samlp",
		Tag:   "AuthnRequest",
	}
	id := "_97e34c50-65ec-4132-8b39-02933960a96a"
	authnRequest.CreateAttr("ID", id)
	hash := crypto.SHA256.New()
	canonicalized, err := ctx.Canonicalizer.Canonicalize(authnRequest)
	require.NoError(t, err)

	_, err = hash.Write(canonicalized)
	require.NoError(t, err)
	digest := hash.Sum(nil)

	signed, err := ctx.SignEnveloped(authnRequest)
	require.NoError(t, err)
	require.NotEmpty(t, signed)

	sig := signed.FindElement("//" + SignatureTag)
	require.NotEmpty(t, sig)

	signedInfo := sig.FindElement("//" + SignedInfoTag)
	require.NotEmpty(t, signedInfo)

	canonicalizationMethodElement := signedInfo.FindElement("//" + CanonicalizationMethodTag)
	require.NotEmpty(t, canonicalizationMethodElement)

	canonicalizationMethodAttr := canonicalizationMethodElement.SelectAttr(AlgorithmAttr)
	require.NotEmpty(t, canonicalizationMethodAttr)
	require.Equal(t, CanonicalXML11AlgorithmId.String(), canonicalizationMethodAttr.Value)

	signatureMethodElement := signedInfo.FindElement("//" + SignatureMethodTag)
	require.NotEmpty(t, signatureMethodElement)

	signatureMethodAttr := signatureMethodElement.SelectAttr(AlgorithmAttr)
	require.NotEmpty(t, signatureMethodAttr)
	require.Equal(t, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", signatureMethodAttr.Value)

	referenceElement := signedInfo.FindElement("//" + ReferenceTag)
	require.NotEmpty(t, referenceElement)

	idAttr := referenceElement.SelectAttr(URIAttr)
	require.NotEmpty(t, idAttr)
	require.Equal(t, "#"+id, idAttr.Value)

	transformsElement := referenceElement.FindElement("//" + TransformsTag)
	require.NotEmpty(t, transformsElement)

	transformElement := transformsElement.FindElement("//" + TransformTag)
	require.NotEmpty(t, transformElement)

	algorithmAttr := transformElement.SelectAttr(AlgorithmAttr)
	require.NotEmpty(t, algorithmAttr)
	require.Equal(t, EnvelopedSignatureAltorithmId.String(), algorithmAttr.Value)

	digestMethodElement := referenceElement.FindElement("//" + DigestMethodTag)
	require.NotEmpty(t, digestMethodElement)

	digestMethodAttr := digestMethodElement.SelectAttr(AlgorithmAttr)
	require.NotEmpty(t, digestMethodElement)
	require.Equal(t, "http://www.w3.org/2001/04/xmlenc#sha256", digestMethodAttr.Value)

	digestValueElement := referenceElement.FindElement("//" + DigestValueTag)
	require.NotEmpty(t, digestValueElement)
	require.Equal(t, base64.StdEncoding.EncodeToString(digest), digestValueElement.Text())
}

func TestSignErrors(t *testing.T) {
	randomKeyStore := RandomKeyStoreForTest()
	ctx := &SigningContext{
		Hash:        crypto.SHA512_256,
		KeyStore:    randomKeyStore,
		IdAttribute: DefaultIdAttr,
		Prefix:      DefaultPrefix,
	}

	authnRequest := &etree.Element{
		Space: "samlp",
		Tag:   "AuthnRequest",
	}

	_, err := ctx.SignEnveloped(authnRequest)
	require.Error(t, err)
}

func TestSignNonDefaultID(t *testing.T) {
	// Sign a document by referencing a non-default ID attribute ("OtherID"),
	// and confirm that the signature correctly references it.
	ks := RandomKeyStoreForTest()
	ctx := &SigningContext{
		Hash:          crypto.SHA256,
		KeyStore:      ks,
		IdAttribute:   "OtherID",
		Prefix:        DefaultPrefix,
		Canonicalizer: MakeC14N11Canonicalizer(),
	}

	signable := &etree.Element{
		Space: "foo",
		Tag:   "Bar",
	}

	id := "_97e34c50-65ec-4132-8b39-02933960a96b"

	signable.CreateAttr("OtherID", id)
	signed, err := ctx.SignEnveloped(signable)
	require.NoError(t, err)

	ref := signed.FindElement("./Signature/SignedInfo/Reference")
	require.NotNil(t, ref)
	refURI := ref.SelectAttrValue("URI", "")
	require.Equal(t, refURI, "#"+id)
}
