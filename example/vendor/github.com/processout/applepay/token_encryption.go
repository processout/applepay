package applepay

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"math/big"

	"github.com/pkg/errors"
)

// DecryptResponse calls DecryptToken(r.Token)
func (m Merchant) DecryptResponse(r *Response) (*Token, error) {
	return m.DecryptToken(&r.Token)
}

// DecryptToken decrypts an Apple Pay token
func (m Merchant) DecryptToken(t *PKPaymentToken) (*Token, error) {
	if m.processingCertificate == nil {
		return nil, errors.New("nil processing certificate")
	}
	// Verify the signature before anything
	if err := t.verifySignature(); err != nil {
		return nil, errors.Wrap(err, "invalid token signature")
	}

	var key []byte
	var err error
	switch version(t.PaymentData.Version) {
	case vEC_v1:
		// Compute the encryption key for EC-based tokens
		key, err = m.computeEncryptionKey(t)
	case vRSA_v1:
		// Decrypt the encryption key for RSA-based tokens
		key, err = m.unwrapEncryptionKey(t)
	}
	if err != nil {
		return nil, errors.Wrap(err, "error retrieving the encryption key")
	}

	// Decrypt the token
	plaintextToken, err := t.decrypt(key)
	if err != nil {
		return nil, errors.Wrap(err, "error decrypting the token")
	}

	// Parse the token
	parsedToken := &Token{}
	json.Unmarshal(plaintextToken, parsedToken)

	return parsedToken, nil
}

// EC

// computeEncryptionKey uses the token's ephemeral EC key, the processing
// private key, and the merchant ID to compute the encryption key
// It is only used for the EC_v1 format
func (m Merchant) computeEncryptionKey(t *PKPaymentToken) ([]byte, error) {
	// Load the required keys
	pub, err := t.ephemeralPublicKey()
	if err != nil {
		return nil, errors.Wrap(err, "unable to parse the public key")
	}
	priv, ok := m.processingCertificate.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("non-elliptic processing private key")
	}

	// Generate the shared secret
	sharedSecret := ecdheSharedSecret(pub, priv)

	// Final key derivation from the shared secret and the hash of the merchant ID
	key := deriveEncryptionKey(sharedSecret, m.identifierHash())

	return key, nil
}

// ephemeralPublicKey parsed the ephemeral public key in a PKPaymentToken
func (t PKPaymentToken) ephemeralPublicKey() (*ecdsa.PublicKey, error) {
	// Parse the ephemeral public key
	pubI, err := x509.ParsePKIXPublicKey(
		t.PaymentData.Header.EphemeralPublicKey,
	)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing the public key")
	}
	pub, ok := pubI.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("invalid EC public key")
	}
	return pub, nil
}

// ecdheSharedSecret computes the shared secret between an EC public key and a
// EC private key, according to RFC5903 Section 9
func ecdheSharedSecret(pub *ecdsa.PublicKey, priv *ecdsa.PrivateKey) *big.Int {
	z, _ := priv.Curve.ScalarMult(pub.X, pub.Y, priv.D.Bytes())
	return z
}

// deriveEncryptionKey derives the symmetric encryption key of the token payload
// from a ECDHE shared secret and a hash of the merchant ID
// It uses the function described in NIST SP 800-56A, section 5.8.1
// See https://developer.apple.com/library/content/documentation/PassKit/Reference/PaymentTokenJSON/PaymentTokenJSON.html#//apple_ref/doc/uid/TP40014929-CH8-SW2
func deriveEncryptionKey(sharedSecret *big.Int, merchantIDHash []byte) []byte {
	// Only one round of the function is required
	counter := []byte{0, 0, 0, 1}
	// Apple-defined KDF parameters
	kdfAlgorithm := []byte("\x0Did-aes256-GCM")
	kdfPartyU := []byte("Apple")
	kdfPartyV := merchantIDHash

	// SHA256( counter || sharedSecret || algorithm || partyU || partyV )
	h := sha256.New()
	h.Write(counter)
	h.Write(sharedSecret.Bytes())
	h.Write(kdfAlgorithm)
	h.Write(kdfPartyU)
	h.Write(kdfPartyV)

	return h.Sum(nil)
}

// RSA

// unwrapEncryptionKey uses the merchant's RSA processing key to decrypt the
// encryption key stored in the token
// It is only used for the RSA_v1 format
func (m Merchant) unwrapEncryptionKey(t *PKPaymentToken) ([]byte, error) {
	priv, ok := m.processingCertificate.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("processing key is not RSA")
	}

	cipherText := t.PaymentData.Header.WrappedKey
	if cipherText == nil {
		return nil, errors.New("empty key ciphertext")
	}

	hash := sha256.New()
	key, err := rsa.DecryptOAEP(hash, rand.Reader, priv, cipherText, nil)
	if err != nil {
		return nil, errors.Wrap(err, "error decrypting the key")
	}

	return key, nil
}

// AES

// decrypt does the symmetric decryption of the payment token using AES-256-GCM
func (t *PKPaymentToken) decrypt(key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.Wrap(err, "error creating the block cipher")
	}
	// Block size 16 mandated by Apple, works with the default 12
	aesGCM, _ := cipher.NewGCMWithNonceSize(block, 16)
	nonce := make([]byte, aesGCM.NonceSize())
	plaintext, err := aesGCM.Open(nil, nonce, t.PaymentData.Data, nil)
	if err != nil {
		return nil, errors.Wrap(err, "error decrypting the data")
	}
	return plaintext, nil
}
