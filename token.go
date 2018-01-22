package applepay

import (
	"time"

	"github.com/pkg/errors"
)

type (
	// PKPaymentToken is the payment information returned by Apple Pay with
	// all data, and an encrypted token
	// See https://developer.apple.com/library/content/documentation/PassKit/Reference/PaymentTokenJSON/PaymentTokenJSON.html
	PKPaymentToken struct {
		transactionTime       time.Time
		TransactionIdentifier string
		PaymentMethod         PaymentMethod
		PaymentData           PaymentData
	}

	PaymentMethod struct {
		Type        string
		Network     string
		DisplayName string
	}

	PaymentData struct {
		Version   string
		Signature []byte
		Header    Header
		Data      []byte
	}

	Header struct {
		ApplicationData    string
		EphemeralPublicKey []byte
		WrappedKey         []byte
		PublicKeyHash      []byte
		TransactionID      string
	}

	// Token is the decrypted form of Response.Token.PaymentData.Data
	Token struct {
		// ApplicationPrimaryAccountNumber is the device-specific account number of the card that funds this
		// transaction
		ApplicationPrimaryAccountNumber string
		// ApplicationExpirationDate is the card expiration date in the format YYMMDD
		ApplicationExpirationDate string
		// CurrencyCode is the ISO 4217 numeric currency code, as a string to preserve leading zeros
		CurrencyCode string
		// TransactionAmount is the value of the transaction
		TransactionAmount float64
		// CardholderName is the name on the card
		CardholderName string
		// DeviceManufacturerIdentifier is a hex-encoded device manufacturer identifier
		DeviceManufacturerIdentifier string
		// PaymentDataType is either 3DSecure or, if using Apple Pay in China, EMV
		PaymentDataType string
		// PaymentData contains detailed payment data
		PaymentData struct {
			// 3-D Secure fields

			// OnlinePaymentCryptogram is the 3-D Secure cryptogram
			OnlinePaymentCryptogram []byte
			// ECIIndicator is the Electronic Commerce Indicator for the status of 3-D Secure
			ECIIndicator string

			// EMV fields

			// EMVData is the output from the Secure Element
			EMVData []byte
			// EncryptedPINData is the PIN encrypted with the bank's key
			EncryptedPINData string
		}
	}

	// version is used to represent the different versions of encryption used by Apple Pay
	version string
)

const (
	vEC_v1  version = "EC_v1"
	vRSA_v1 version = "RSA_v1"
)

var (
	// This section contains all modifiable settings of the package

	// AppleRootCertificatePath is the relative path to Apple's root certificate
	AppleRootCertificatePath = "AppleRootCA-G3.crt"

	// TransactionTimeWindow is the window of time, in minutes, where
	// transactions can fit to limit replay attacks
	TransactionTimeWindow = 5 * time.Minute
)

// PublicKeyHash returns the hash of the public key used in the token after
// checking the message's signature. This is useful for selecting the
// appropriate processing key for merchants/PSPs that may have many.
func (t PKPaymentToken) PublicKeyHash() ([]byte, error) {
	if err := t.verifySignature(); err != nil {
		return nil, errors.Wrap(err, "invalid token signature")
	}
	return t.PaymentData.Header.PublicKeyHash, nil
}

// SetTransactionTime sets the time the merchant received the token. This
// is useful to protect against replay attacks. By default this value is set to
// time.Now(), when the token is decrypted.
// It may be useful to change the transaction time window (see the global
// variable TransactionTimeWindow)
func (t *PKPaymentToken) SetTransactionTime(transactionTime time.Time) error {
	if t == nil {
		return errors.New("nil token")
	}

	t.transactionTime = transactionTime
	return nil
}

// checkVersion verifies if the token's version of the encryption protocol is
// supported. We support EC_v1 and RSA_v1.
func (t PKPaymentToken) checkVersion() error {
	if version(t.PaymentData.Version) == vEC_v1 {
		return nil
	}
	if version(t.PaymentData.Version) == vRSA_v1 {
		return nil
	}
	return errors.Errorf("unsupported version %s", t.PaymentData.Version)
}

// String implements fmt.Stringer for version
func (v version) String() string {
	return string(v)
}
