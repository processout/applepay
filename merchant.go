package applepay

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"strings"

	"github.com/pkg/errors"
)

type (
	Merchant struct {
		// General configuration
		identifier  string
		displayName string
		domainName  string

		// Merchant Identity Certificate
		merchantCertificate *tls.Certificate
		// Payment Processing Certificate
		processingCertificate *tls.Certificate
	}
)

var (
	// merchantIDHashOID is the ASN.1 object identifier of Apple's extension
	// for merchant ID hash in merchant/processing certificates
	merchantIDHashOID = mustParseASN1ObjectIdentifier(
		"1.2.840.113635.100.6.32",
	)
)

// New creates an instance of Merchant using the given configuration
func New(merchantID string, options ...func(*Merchant) error) (*Merchant, error) {
	if !strings.HasPrefix(merchantID, "merchant.") {
		return nil, errors.New("merchant ID should start with `merchant.`")
	}

	m := &Merchant{identifier: merchantID}
	for _, option := range options {
		err := option(m)
		if err != nil {
			return nil, err
		}
	}
	return m, nil
}

// identifierHash hashes m.config.MerchantIdentifier with SHA-256
func (m *Merchant) identifierHash() []byte {
	h := sha256.New()
	h.Write([]byte(m.identifier))
	return h.Sum(nil)
}

func MerchantDisplayName(displayName string) func(*Merchant) error {
	return func(m *Merchant) error {
		m.displayName = displayName
		return nil
	}
}

func MerchantDomainName(domainName string) func(*Merchant) error {
	return func(m *Merchant) error {
		m.domainName = domainName
		return nil
	}
}

func MerchantCertificate(cert tls.Certificate) func(*Merchant) error {
	return func(m *Merchant) error {
		// Check that the certificate is RSA
		if _, ok := cert.PrivateKey.(*rsa.PrivateKey); !ok {
			return errors.New("merchant key should be RSA")
		}

		if err := checkValidity(cert); err != nil {
			return errors.Wrap(err, "invalid certificate")
		}

		// Verify merchant ID
		hash, err := extractMerchantHash(cert)
		if err != nil {
			return errors.Wrap(err, "error reading the certificate")
		}
		if !bytes.Equal(hash, m.identifierHash()) {
			return errors.New("invalid merchant certificate or merchant ID")
		}
		m.merchantCertificate = &cert
		return nil
	}
}

func ProcessingCertificate(cert tls.Certificate) func(*Merchant) error {
	return func(m *Merchant) error {
		if err := checkValidity(cert); err != nil {
			return errors.Wrap(err, "invalid certificate")
		}

		// Verify merchant ID
		hash, err := extractMerchantHash(cert)
		if err != nil {
			return errors.Wrap(err, "error reading the certificate")
		}
		if !bytes.Equal(hash, m.identifierHash()) {
			return errors.New("invalid processing certificate or merchant ID")
		}
		m.processingCertificate = &cert
		return nil
	}
}

func MerchantCertificateLocation(certLocation,
	keyLocation string) func(*Merchant) error {

	return loadCertificate(certLocation, keyLocation, MerchantCertificate)
}

func ProcessingCertificateLocation(certLocation,
	keyLocation string) func(*Merchant) error {

	return loadCertificate(certLocation, keyLocation, ProcessingCertificate)
}

func loadCertificate(certLocation, keyLocation string,
	callback func(tls.Certificate) func(*Merchant) error) func(
	*Merchant) error {

	return func(m *Merchant) error {
		cert, err := tls.LoadX509KeyPair(certLocation, keyLocation)
		if err != nil {
			return errors.Wrap(err, "error loading the certificate")
		}
		return callback(cert)(m)
	}
}
