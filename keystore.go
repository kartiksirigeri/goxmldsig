package dsig

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"math/big"
	"time"
)

type X509KeyStore interface {
	GetKeyPair() (privateKey *rsa.PrivateKey, cert []byte, err error)
}

type X509ChainStore interface {
	GetChain() (certs [][]byte, err error)
}

type X509CertificateStore interface {
	Certificates() (roots []*x509.Certificate, err error)
}

type MemoryX509CertificateStore struct {
	Roots []*x509.Certificate
}

func (mX509cs *MemoryX509CertificateStore) Certificates() ([]*x509.Certificate, error) {
	return mX509cs.Roots, nil
}

type MemoryX509KeyStore struct {
	privateKey *rsa.PrivateKey
	cert       []byte
}

func (ks *MemoryX509KeyStore) GetKeyPair() (*rsa.PrivateKey, []byte, error) {
	return ks.privateKey, ks.cert, nil
}

func (ks *MemoryX509KeyStore) SetKeyPair(savePrivateKey *rsa.PrivateKey, saveCert []byte) {
	ks.privateKey, ks.cert =  savePrivateKey, saveCert
}

func RandomKeyStoreForTest() X509KeyStore {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	now := time.Now()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(0),
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(365 * 24 * time.Hour),

		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{},
		BasicConstraintsValid: true,
	}

	if err != nil {
		panic(err)
	}
	cert, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)

	//pemCrtBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})
	//fmt.Printf("%s", string(pemCrtBytes))
	//
	//pemKeyBytes := pem.EncodeToMemory(
	//	&pem.Block{
	//		Type: "RSA PRIVATE KEY",
	//		Bytes: x509.MarshalPKCS1PrivateKey(key),
	//	},
	//)
	//fmt.Printf("%s", string(pemKeyBytes))


	return &MemoryX509KeyStore{
		privateKey: key,
		cert:       cert,
	}
}
