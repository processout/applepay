package applepay

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/pkg/errors"
	"go.mozilla.org/pkcs7"
)

var (
	leafCertificateOID  = mustParseASN1ObjectIdentifier("1.2.840.113635.100.6.29")
	interCertificateOID = mustParseASN1ObjectIdentifier("1.2.840.113635.100.6.2.14")
)

// verifySignature checks the signature of the token, partially using OpenSSL
// due to Go's lack of support for PKCS7.
// See https://developer.apple.com/library/content/documentation/PassKit/Reference/PaymentTokenJSON/PaymentTokenJSON.html#//apple_ref/doc/uid/TP40014929-CH8-SW2
func (t *PKPaymentToken) verifySignature() error {
	if err := t.checkVersion(); err != nil {
		return errors.Wrap(err, "invalid version")
	}

	// parse p7
	p7, err := pkcs7.Parse(t.PaymentData.Signature)
	if err != nil {
		return fmt.Errorf("cannot parse our signed data: %s", err.Error())
	}

	root, err := loadRootCertificate(AppleRootCertificatePath)
	if err != nil {
		return errors.Wrap(err, "error loading the root certificate")
	}

	if len(p7.Certificates) < 2 {
		return errors.New("the len of certificates is less than 2")
	}

	// Load
	inter := p7.Certificates[1]
	leaf := p7.Certificates[0]

	// Verify
	if err := verifyCertificates(root, inter, leaf); err != nil {
		return errors.Wrap(err, "error when verifying the certificates")
	}

	// create the cert poll with iter and leaf
	pool := x509.NewCertPool()
	pool.AddCert(root)
	pool.AddCert(leaf)
	pool.AddCert(inter)

	// verifyPKCS7Signature verifies that the signature was produced by the leaf
	// certificate contained in the given PKCS7 struct
	if err := p7.VerifyWithChain(pool); err != nil {
		return err
	}

	if err := t.verifySigningTime(p7); err != nil {
		return errors.Wrap(
			err,
			"rejected signing time delta (possible replay attack)",
		)
	}

	return nil
}

// loadRootCertificate loads the root certificate from the disk
func loadRootCertificate(path string) (*x509.Certificate, error) {
	rootPEMBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, errors.Wrap(err, "error reading the root certificate")
	}
	rootPEM, rest := pem.Decode(rootPEMBytes)
	if rootPEM == nil {
		return nil, errors.New("error decoding the root certificate")
	}
	if rest != nil && len(rest) > 0 {
		return nil, errors.New("trailing data after the root certificate")
	}

	root, err := x509.ParseCertificate(rootPEM.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing the root certificate")
	}
	if !root.IsCA {
		return nil, errors.New("the certificate seems not to be a CA")
	}

	return root, nil
}

// verifyCertificates checks the validity of the certificate chain used for
// signing the token, and verifies the chain of trust from root to leaf
func verifyCertificates(root, inter, leaf *x509.Certificate) error {
	// Ensure the certificates contain the correct OIDs
	if _, err := extractExtension(inter, interCertificateOID); err != nil {
		return errors.Wrap(err, "invalid intermediate cert Apple extension")
	}
	if _, err := extractExtension(leaf, leafCertificateOID); err != nil {
		return errors.Wrap(err, "invalid leaf cert Apple extension")
	}

	// Verify the chain of trust
	if err := inter.CheckSignatureFrom(root); err != nil {
		return errors.Wrap(err, "intermediate cert is not trusted by root")
	}
	if err := leaf.CheckSignatureFrom(inter); err != nil {
		return errors.Wrap(err, "leaf cert is not trusted by intermediate cert")
	}

	return nil
}

// signedData returns the data signed by the client's Secure Element as defined
// in Apple's documentation: https://developer.apple.com/library/content/documentation/PassKit/Reference/PaymentTokenJSON/PaymentTokenJSON.html#//apple_ref/doc/uid/TP40014929-CH8-SW2
func (t PKPaymentToken) signedData() []byte {
	signed := bytes.NewBuffer(nil)

	switch version(t.PaymentData.Version) {
	case vEC_v1:
		signed.Write(t.PaymentData.Header.EphemeralPublicKey)
	case vRSA_v1:
		signed.Write(t.PaymentData.Header.WrappedKey)
	}

	signed.Write(t.PaymentData.Data)
	trIDHex, _ := hex.DecodeString(t.PaymentData.Header.TransactionID)
	signed.Write(trIDHex)
	appDataHex, _ := hex.DecodeString(t.PaymentData.Header.ApplicationData)
	signed.Write(appDataHex)
	return signed.Bytes()
}

// verifySigningTime checks that the time of signing of the token is before the
// transaction was received, and that the gap between the two is not too
// significant. It uses the variable TransactionTimeWindow as a limit.
func (t PKPaymentToken) verifySigningTime(p7 *pkcs7.PKCS7) error {
	transactionTime := time.Now()
	if !t.transactionTime.IsZero() {
		transactionTime = t.transactionTime
	}

	signedTime := time.Time{}
	if err := p7.UnmarshalSignedAttribute(pkcs7.OIDAttributeSigningTime, &signedTime); err != nil {
		return err
	}

	// Check that both times are separated by less than TransactionTimeWindow
	delta := transactionTime.Sub(signedTime)
	if delta < -time.Second {
		return errors.Errorf(
			"the transaction occured before the signing (%s difference)",
			delta.String(),
		)
	}
	if delta > TransactionTimeWindow {
		return errors.Errorf(
			"the transaction occured after the allowed time window (%s)",
			delta.String(),
		)
	}
	return nil
}
