package applepay

/*
#cgo CFLAGS: -I/usr/local/opt/openssl/include
#cgo LDFLAGS: -L/usr/local/opt/openssl/lib
#cgo pkg-config: openssl
#include <openssl/x509v3.h>
#include <openssl/err.h>

// Replace macros for cgo
X509* sk_X509_value_func(STACK_OF(X509) *sk, int i) { return sk_X509_value(sk, i); }
void OpenSSL_add_all_algorithms_func() { OpenSSL_add_all_algorithms(); }
int sk_PKCS7_SIGNER_INFO_num_func(STACK_OF(PKCS7_SIGNER_INFO) *sk) { return sk_PKCS7_SIGNER_INFO_num(sk); }
PKCS7_SIGNER_INFO *sk_PKCS7_SIGNER_INFO_value_func(STACK_OF(PKCS7_SIGNER_INFO) *sk, int i) { return sk_PKCS7_SIGNER_INFO_value(sk, i); }
*/
import "C"

import (
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"io/ioutil"
	"time"
	"unsafe"

	"github.com/pkg/errors"
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

	// Load
	p7, inter, leaf, err := t.decodePKCS7()
	if err != nil {
		return errors.Wrap(err, "error decoding the token signature")
	}
	root, err := loadRootCertificate(AppleRootCertificatePath)
	if err != nil {
		return errors.Wrap(err, "error loading the root certificate")
	}

	// Verify
	if err := verifyCertificates(root, inter, leaf); err != nil {
		return errors.Wrap(err, "error when verifying the certificates")
	}
	if err := t.verifyPKCS7Signature(p7); err != nil {
		return errors.Wrap(err, "error verifying the PKCS7 signature")
	}
	if err := t.verifySigningTime(p7); err != nil {
		return errors.Wrap(
			err,
			"rejected signing time delta (possible replay attack)",
		)
	}

	return nil
}

// decodePKCS7 decodes the raw payment token signature field into an OpenSSL
// PKCS7 struct, and returns the intermediary and leaf certificates used for the
// signature
func (t PKPaymentToken) decodePKCS7() (p7 *C.PKCS7, inter,
	leaf *x509.Certificate, err error) {

	// Decode PKCS7 blob, certificate chain
	pkcs7Bio := newBIOBytes(t.PaymentData.Signature)
	defer pkcs7Bio.Free()
	p7 = C.d2i_PKCS7_bio(pkcs7Bio.C(), nil)
	if p7 == nil {
		err = errors.New("openssl error: could not decode PKCS7")
		return
	}
	sign := (*C.PKCS7_SIGNED)(union(p7.d))

	if sign == nil {
		err = errors.New("openssl error: error dereferencing d in PKCS7")
		return
	}
	// Decode intermediate and leaf certificates
	if inter, leaf, err = decodeIntermediateAndLeafCert(sign); err != nil {
		err = errors.Wrap(err, "error decoding the embedded certificates")
		return
	}

	return p7, inter, leaf, nil
}

// decodeIntermediateAndLeafCert decodes the intermediary and leaf certificates
// of the PKCS7 object
func decodeIntermediateAndLeafCert(sign *C.PKCS7_SIGNED) (inter,
	leaf *x509.Certificate, err error) {

	const interCertIndex = 1
	const leafCertIndex = 0

	// C structs -> DER
	// TODO: check stack length
	interBio, leafBio := newBIO(), newBIO()
	defer interBio.Free()
	defer leafBio.Free()
	r := C.i2d_X509_bio(
		interBio.C(),
		C.sk_X509_value_func(sign.cert, interCertIndex),
	)
	if r != 1 {
		err = errors.Wrap(opensslErr(), "error encoding the intermediate cert")
		return
	}
	r = C.i2d_X509_bio(
		leafBio.C(),
		C.sk_X509_value_func(sign.cert, leafCertIndex),
	)
	if r != 1 {
		err = errors.Wrap(opensslErr(), "error encoding the leaf cert")
		return
	}

	// DER -> Go structs
	if inter, err = x509.ParseCertificate(interBio.ReadAll()); err != nil {
		err = errors.Wrap(err, "error decoding the intermediate certificate")
		return
	}
	if leaf, err = x509.ParseCertificate(leafBio.ReadAll()); err != nil {
		err = errors.Wrap(err, "error decoding the leaf certificate")
		return
	}
	return
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

// verifyPKCS7Signature verifies that the signature was produced by the leaf
// certificate contained in the given PKCS7 struct
func (t PKPaymentToken) verifyPKCS7Signature(p7 *C.PKCS7) error {
	// TODO: use the Go x509 API instead of OpenSSL
	// This code does not work for some reason:
	// if err := leaf.CheckSignature(leaf.SignatureAlgorithm, t.signedData(),
	//     signatureBytes); err != nil {
	//
	//     return errors.Wrap(err, "invalid signature")
	// }

	C.OpenSSL_add_all_algorithms_func()
	//defer C.EVP_cleanup()
	signedDataBio := newBIOBytes(t.signedData())
	defer signedDataBio.Free()
	// The PKCS7_NOVERIFY flag corresponds to verifying the chain of trust of
	// the certificates, which should have been done before
	r := C.PKCS7_verify(p7, nil, nil, signedDataBio.C(), nil, C.PKCS7_NOVERIFY)
	if r != 1 {
		return errors.Wrap(opensslErr(), "signature validation error")
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
func (t PKPaymentToken) verifySigningTime(p7 *C.PKCS7) error {
	transactionTime := time.Now()
	if !t.transactionTime.IsZero() {
		transactionTime = t.transactionTime
	}

	signingTime, err := t.extractSigningTime(p7)
	if err != nil {
		return errors.Wrap(err, "error reading the signing time from the token")
	}

	// Check that both times are separated by less than TransactionTimeWindow
	delta := transactionTime.Sub(signingTime)
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

// extractSigningTime returns the time of signing from a PKCS7 struct
func (t PKPaymentToken) extractSigningTime(p7 *C.PKCS7) (time.Time, error) {
	signerInfoList := C.PKCS7_get_signer_info(p7)
	if signerInfoList == nil {
		return time.Time{},
			errors.New("openssl error when extracting signer information")
	}

	// Find the right SIGNER_INFO field
	signerInfoListSize := int(C.sk_PKCS7_SIGNER_INFO_num_func(signerInfoList))
	var signingTime time.Time
	for i := 0; i < signerInfoListSize; i++ {
		si := C.sk_PKCS7_SIGNER_INFO_value_func(signerInfoList, C.int(i))
		if si == nil {
			continue
		}
		so := C.PKCS7_get_signed_attribute(si, C.NID_pkcs9_signingTime)
		if so == nil || so._type != C.V_ASN1_UTCTIME {
			continue
		}

		// Decode the signing time
		stBio := newBIO()
		r := C.ASN1_UTCTIME_print(stBio.C(), (*C.ASN1_UTCTIME)(union(so.value)))
		if r != 1 {
			stBio.Free()
			return time.Time{}, errors.Wrap(opensslErr(), "time encoding error")
		}
		pt, err := time.Parse("Jan _2 15:04:05 2006 MST", stBio.ReadAllString())
		if err != nil {
			stBio.Free()
			return time.Time{}, errors.Wrap(err, "error parsing time")
		}
		signingTime = pt
		stBio.Free()
		break
	}
	if signingTime.IsZero() {
		return time.Time{}, errors.New("signing time not found")
	}

	return signingTime, nil
}

// union dereferences a union pointer so that its value can be used
// Don't do this at home!
func union(union [8]byte) unsafe.Pointer {
	dBuf := bytes.NewBuffer(union[:])
	var ptr uint64
	binary.Read(dBuf, binary.LittleEndian, &ptr)
	return unsafe.Pointer(uintptr(ptr))
}

// opensslErr reads the errors from OpenSSL into a Go error
func opensslErr() error {
	errOut := newBIO()
	defer errOut.Free()
	C.ERR_print_errors(errOut.C())
	return errors.New(errOut.ReadAllString())
}
