// In-enclave CA for TLS interception.
//
// The CA key is generated at startup, lives only in memory, and never leaves
// the CVM. It is trusted by exactly one party — the executor, which receives
// the CA certificate over the execsock unix socket at session init. Nothing
// outside the sandbox ever sees a certificate this CA issued.
//
// Interception toward the sandbox does not mean laxity toward the internet:
// the upstream leg verifies origin certificates against the system roots
// normally, and the observed origin certificate hash is recorded in the audit
// entry so a reader can confirm afterwards which server was actually reached.
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
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"
)

const (
	caCommonName = "Tinfoil Sandbox Egress CA"
	leafTTL      = 24 * time.Hour
	maxLeafCache = 512
)

// CA mints per-host leaf certificates for interception.
type CA struct {
	key    *ecdsa.PrivateKey
	cert   *x509.Certificate
	certPE []byte
	fp     string

	mu    sync.Mutex
	leafs map[string]*tls.Certificate
}

func NewCA() (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating CA key: %w", err)
	}

	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: caCommonName},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, fmt.Errorf("self-signing CA: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parsing CA: %w", err)
	}
	sum := sha256.Sum256(der)

	return &CA{
		key:    key,
		cert:   cert,
		certPE: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		fp:     hex.EncodeToString(sum[:]),
		leafs:  make(map[string]*tls.Certificate),
	}, nil
}

// CertPEM is what the executor installs as a trust anchor.
func (c *CA) CertPEM() string { return string(c.certPE) }

// Fingerprint is recorded in session.start so a transcript reader can tell
// which CA was in force for the intercepted entries.
func (c *CA) Fingerprint() string { return c.fp }

// LeafFor returns a certificate for host, minting and caching on miss.
func (c *CA) LeafFor(host string) (*tls.Certificate, error) {
	c.mu.Lock()
	if leaf, ok := c.leafs[host]; ok {
		c.mu.Unlock()
		return leaf, nil
	}
	c.mu.Unlock()

	leaf, err := c.mint(host)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	// Bound the cache. The executor picks the hostnames, so this must not be
	// allowed to grow without limit; a plain reset is fine at this size.
	if len(c.leafs) >= maxLeafCache {
		c.leafs = make(map[string]*tls.Certificate, maxLeafCache)
	}
	c.leafs[host] = leaf
	return leaf, nil
}

func (c *CA) mint(host string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating leaf key for %s: %w", host, err)
	}
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(leafTTL),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, key.Public(), c.key)
	if err != nil {
		return nil, fmt.Errorf("signing leaf for %s: %w", host, err)
	}
	return &tls.Certificate{
		Certificate: [][]byte{der, c.cert.Raw},
		PrivateKey:  key,
		Leaf:        tmpl,
	}, nil
}

func randSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generating serial: %w", err)
	}
	return n, nil
}
