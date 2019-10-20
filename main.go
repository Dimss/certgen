// based on source: https://shaneutt.com/blog/golang-ca-and-signed-cert-go/
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
	"encoding/base64"
)

type CACerts struct {
	CA           *x509.Certificate
	CAPrivateKey *rsa.PrivateKey
	CAPem        []byte
	CAPrivPem    []byte
}

func (ca *CACerts) generateRootCerts() (err error) {
	// Create root certificate template
	ca.CA = &x509.Certificate{
		SerialNumber:          big.NewInt(2019),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(100, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	// Generate root private key
	ca.CAPrivateKey, err = rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		fmt.Println(err, "failed to generate CA PRIVATE KEY")
		return err
	}
	// Create root certificate
	caBytes, err := x509.CreateCertificate(rand.Reader, ca.CA, ca.CA, &ca.CAPrivateKey.PublicKey, ca.CAPrivateKey)
	if err != nil {
		fmt.Println(err, "failed to generate CA crt ")
		return err
	}
	// Encode certificate into base64 byte array
	caPEM := new(bytes.Buffer)
	err = pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})
	// Read from buffer
	ca.CAPem = caPEM.Bytes()
	if err != nil {
		fmt.Print(fmt.Errorf("%v", err))
	}

	return nil
}

func (ca *CACerts) generateCertificates(serviceName string) (crt []byte, key []byte, err error) {
	// Create certificate
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject:      pkix.Name{CommonName: serviceName,},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	// Generate private key
	certPrivKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		fmt.Println(err, "failed to generate certPrivKey for client certificate")
		return nil, nil, err
	}
	// Generate certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca.CA, &certPrivKey.PublicKey, ca.CAPrivateKey)
	if err != nil {
		fmt.Println(err, "failed to create certificate")
		return nil, nil, err
	}
	// Encode certificate to base64 byte array
	certPEM := new(bytes.Buffer)
	err = pem.Encode(certPEM, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes,})
	if err != nil {
		fmt.Println(err, "failed to encode certificate")
		return nil, nil, err
	}
	// Encode key to base64 byte array
	certPrivKeyPEM := new(bytes.Buffer)
	err = pem.Encode(certPrivKeyPEM, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),})
	if err != nil {
		fmt.Println(err, "failed to encode key")
		return nil, nil, err
	}
	// Read from buffers and return results
	crt = certPEM.Bytes()
	key = certPrivKeyPEM.Bytes()
	return crt, key, nil
}

func main() {
	ca := CACerts{}
	if err := ca.generateRootCerts(); err != nil {
		fmt.Println(err)
	}
	fmt.Printf("CABundle: %v \n", base64.StdEncoding.EncodeToString(ca.CAPem))

	cert, key, err := ca.generateCertificates("darp-service.darp.svc")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("server.crt: %v \n", base64.StdEncoding.EncodeToString(cert))
	fmt.Printf("server.key: %v", base64.StdEncoding.EncodeToString(key))

}
