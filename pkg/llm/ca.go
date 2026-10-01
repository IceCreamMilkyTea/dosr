package llm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"
)

// CA is a private, in-memory certificate authority for tests, local
// testnets and benchmarks. The mock provider serves a certificate issued
// by it and the notary is configured with Pool() as its root set, so the
// notary's certificate validation code path is the same as against a real
// provider. It must never be used to protect anything real: the key lives
// in process memory and is not persisted.
type CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	der  []byte
}

// NewCA creates a fresh CA (ECDSA P-256, valid from one hour ago for one
// year).
func NewCA(commonName string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("llm: generating CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"DOSR test CA (not for production)"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("llm: creating CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("llm: parsing CA certificate: %w", err)
	}
	return &CA{cert: cert, key: key, der: der}, nil
}

func randomSerial() (*big.Int, error) {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 126))
	if err != nil {
		return nil, fmt.Errorf("llm: generating serial: %w", err)
	}
	return n.Add(n, big.NewInt(1)), nil
}

// Pool returns a new certificate pool containing only this CA.
func (ca *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.cert)
	return p
}

// CertPEM returns the CA certificate in PEM form (e.g. to write a roots
// file for a notary running in another process).
func (ca *CA) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.der})
}

// Issue creates a server certificate for the given DNS names and/or IP
// addresses (ECDSA P-256, valid from one hour ago for 90 days).
func (ca *CA) Issue(hosts ...string) (tls.Certificate, error) {
	if len(hosts) == 0 {
		return tls.Certificate{}, errors.New("llm: no host names given")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("llm: generating server key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hosts[0]},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("llm: creating server certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("llm: parsing server certificate: %w", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

// NewLocalhostTLS creates a private CA and a server certificate valid for
// "localhost", 127.0.0.1 and ::1. Tests, the notary and benchmarks share
// the result: the provider serves cert, the notary trusts ca.Pool().
func NewLocalhostTLS() (*CA, tls.Certificate, error) {
	ca, err := NewCA("DOSR mock provider CA")
	if err != nil {
		return nil, tls.Certificate{}, err
	}
	cert, err := ca.Issue("localhost", "127.0.0.1", "::1")
	if err != nil {
		return nil, tls.Certificate{}, err
	}
	return ca, cert, nil
}

// SPKIHash returns the SHA-256 of the SubjectPublicKeyInfo of the leaf of
// cert: the value a notary reports as server_spki for connections to a
// server using cert, and what a policy's provider_spki pins.
func SPKIHash(cert tls.Certificate) ([]byte, error) {
	leaf := cert.Leaf
	if leaf == nil {
		if len(cert.Certificate) == 0 {
			return nil, errors.New("llm: empty certificate chain")
		}
		var err error
		if leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
			return nil, fmt.Errorf("llm: parsing leaf certificate: %w", err)
		}
	}
	h := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	return h[:], nil
}
