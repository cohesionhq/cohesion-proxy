package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// newIdentityPEM makes a P-256 key and a self-signed certificate for it, as
// PEM (certificate, then PKCS#8 key) — the same shape `cohesion setup` saves.
// cohesiond identifies clients by key fingerprint, not by the certificate.
func newIdentityPEM(name string) ([]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(100, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	out := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return append(out, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})...), nil
}

// keyFingerprint is lowercase hex SHA-256 of a certificate's
// SubjectPublicKeyInfo, matching cohesion-core's `key_fingerprint`.
func keyFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// clientTLS presents identityPEM to cohesiond and trusts only a server whose
// key matches fingerprint. cohesiond re-signs a self-signed certificate on
// every start, so there is no CA or stable certificate to check; its key is
// what stays the same. Go still verifies the handshake signature, proving the
// server holds that key.
func clientTLS(identityPEM []byte, fingerprint string, alpn ...string) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(identityPEM, identityPEM)
	if err != nil {
		return nil, fmt.Errorf("invalid identity: %w", err)
	}
	if fingerprint == "" {
		return nil, errors.New("no pinned server fingerprint")
	}
	return &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true, // replaced by the pin below
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("cohesiond presented no certificate")
			}
			leaf, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}
			if got := keyFingerprint(leaf); got != fingerprint {
				return fmt.Errorf("cohesiond key fingerprint %s does not match pinned %s", got, fingerprint)
			}
			return nil
		},
		NextProtos: alpn,
		MinVersion: tls.VersionTLS12,
	}, nil
}
