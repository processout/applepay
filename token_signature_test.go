package applepay

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"os"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"github.com/stretchr/testify/require"
	"go.mozilla.org/pkcs7"
)

func TestVerifySignature(t *testing.T) {
	Convey("Invalid versions are rejected", t, func() {
		token := &PKPaymentToken{
			PaymentData: PaymentData{
				Version: "invalid version",
			},
		}
		err := token.verifySignature()

		So(err.Error(), ShouldStartWith, "invalid version")
	})

	// TODO: find a way around testing cgo

	Convey("Valid signatures are accepted", t, func() {
		token := &PKPaymentToken{}
		json.Unmarshal([]byte(`{"transactionIdentifier":"D60E5B29DAAF960C9837D15F1E968E1BB3AD124FE7FA4F85482D7D53789C273F","paymentMethod":{"network":"Visa","type":"debit","displayName":"Visa 3595"},"paymentData":{"version":"EC_v1","header":{"transactionId":"d60e5b29daaf960c9837d15f1e968e1bb3ad124fe7fa4f85482d7d53789c273f","publicKeyHash":"hErQTIkV+XDB8kVuVvYI+1PUv/iIJPuFg2QF/+z1NIo=","ephemeralPublicKey":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEH5hMm7QXtTZBVHqIEg4PZveYt0vkmO1SsIWthxzl8NMBfhtPiUDkvgAKoUAOsTu2WqZxoJqccEX3GwWk4fIEjw=="},"signature":"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","data":"qMvuwnxckj/BzZgR7bR75QqCB+CmEo8AYPJDZl+oD/eZgzcvHB1UfwXdyOIjQk1NX0whfwPZoh6Xfkxvb6g0F9Y/dTtJW4E5aD39NDlaZD5C8XOyDlx27IXCOc5vkEyfV4z1T15wsmYKRl0K+BcmaLbuYEmCQGTwq4Z1LVLhlDpkbtdrqr7WuBH6mIToV4AV+zlTfKj67uLRpmhqBLox14hFkVl3Il15Oq6PnYP2f+padZudUrkjWOPR8pNepPF52EL/mUNadKs3NjqG9uJLl2ELY1A+MESosJ6zoSpKuBBF8FxvaJQgDCJS2yeOut+r8okbh06xVMjNPLC7dGyGW2a6OdpsMGc5+nsP9bs3V6NIosYDCoszEBVFFFjjnYSJhdlER1i6lGE6RTjSUnPGMSb4aknjrDRN/4AJz4Q="}}`), token)

		err := token.verifySignature()

		So(err, ShouldBeNil)
	})
}

func TestLoadRootCertificate(t *testing.T) {
	Convey("Inexisting root certificates produce an error", t, func() {
		cert, err := loadRootCertificate("/tmp/inexisting.crt")

		Convey("cert is nil", func() {
			So(cert, ShouldBeNil)
		})

		Convey("err is correct", func() {
			So(err.Error(), ShouldStartWith, "error reading the root certificate")
		})
	})

	Convey("Invalid PEM blocks are rejected", t, func() {
		f, _ := ioutil.TempFile("/tmp", "test_invalid_pem_block_")
		defer f.Close()
		defer os.Remove(f.Name())
		f.WriteString("invalid pem block")

		cert, err := loadRootCertificate(f.Name())

		Convey("cert is nil", func() {
			So(cert, ShouldBeNil)
		})

		Convey("err is correct", func() {
			So(err.Error(), ShouldStartWith, "error decoding the root certificate")
		})
	})

	Convey("Trailing data after the PEM block makes an error", t, func() {
		f, _ := ioutil.TempFile("/tmp", "test_pem_trailing_data_")
		defer f.Close()
		defer os.Remove(f.Name())
		pem.Encode(f, &pem.Block{
			Type:  "TEST",
			Bytes: []byte("pem data"),
		})
		f.WriteString("invalid trailing data")

		cert, err := loadRootCertificate(f.Name())

		Convey("cert is nil", func() {
			So(cert, ShouldBeNil)
		})

		Convey("err should be correct", func() {
			So(err.Error(), ShouldStartWith, "trailing data after the root certificate")
		})
	})

	Convey("Invalid certificates are rejected", t, func() {
		f, _ := ioutil.TempFile("/tmp", "test_invalid_certificate_")
		defer f.Close()
		defer os.Remove(f.Name())
		pem.Encode(f, &pem.Block{
			Type:  "TEST",
			Bytes: []byte("this is an invalid certificate"),
		})

		cert, err := loadRootCertificate(f.Name())

		Convey("cert is nil", func() {
			So(cert, ShouldBeNil)
		})

		Convey("err should be correct", func() {
			So(err.Error(), ShouldStartWith, "error parsing the root certificate")
		})
	})

	Convey("Non-CA certificates produce an error", t, func() {
		f, _ := ioutil.TempFile("/tmp", "test_non_ca_certificate_")
		defer f.Close()
		defer os.Remove(f.Name())
		tpl := &x509.Certificate{
			SerialNumber: big.NewInt(0),
			IsCA:         false,
		}
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		genCert, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
		pem.Encode(f, &pem.Block{
			Type:  "TEST",
			Bytes: genCert,
		})

		cert, err := loadRootCertificate(f.Name())

		Convey("cert is nil", func() {
			So(cert, ShouldBeNil)
		})

		Convey("err should be correct", func() {
			So(err.Error(), ShouldStartWith, "the certificate seems not to be a CA")
		})
	})

	Convey("Apple's actual root certificate is loaded properly", t, func() {
		cert, err := loadRootCertificate(AppleRootCertificatePath)

		Convey("cert is not nil", func() {
			So(cert, ShouldNotBeNil)
		})

		Convey("err should be nil", func() {
			So(err, ShouldBeNil)
		})
	})
}

func TestVerifyCertificates(t *testing.T) {
	appleRoot, _ := loadRootCertificate(AppleRootCertificatePath)

	rootTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(0),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	testRootBytes, _ := x509.CreateCertificate(rand.Reader, rootTpl, rootTpl, &rootKey.PublicKey, rootKey)
	testRoot, _ := x509.ParseCertificate(testRootBytes)

	Convey("Missing extension in intermediate certificate produces an error", t, func() {
		interTpl := &x509.Certificate{
			SerialNumber:          big.NewInt(0),
			IsCA:                  true,
			BasicConstraintsValid: true,
		}
		interKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		interBytes, _ := x509.CreateCertificate(rand.Reader, interTpl, testRoot, &interKey.PublicKey, rootKey)
		inter, _ := x509.ParseCertificate(interBytes)
		leafTpl := &x509.Certificate{
			SerialNumber: big.NewInt(0),
			ExtraExtensions: []pkix.Extension{
				{
					Id:    leafCertificateOID,
					Value: []byte("test"),
				},
			},
		}
		leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		leafBytes, _ := x509.CreateCertificate(rand.Reader, leafTpl, inter, &leafKey.PublicKey, interKey)
		leaf, _ := x509.ParseCertificate(leafBytes)

		err := verifyCertificates(testRoot, inter, leaf)

		So(err.Error(), ShouldStartWith, "invalid intermediate cert Apple extension")
	})

	Convey("Missing extension in leaf certificate produces an error", t, func() {
		interTpl := &x509.Certificate{
			SerialNumber: big.NewInt(0),
			ExtraExtensions: []pkix.Extension{
				{
					Id:    interCertificateOID,
					Value: []byte("test"),
				},
			},
			IsCA:                  true,
			BasicConstraintsValid: true,
		}
		interKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		interBytes, _ := x509.CreateCertificate(rand.Reader, interTpl, testRoot, &interKey.PublicKey, rootKey)
		inter, _ := x509.ParseCertificate(interBytes)
		leafTpl := &x509.Certificate{
			SerialNumber: big.NewInt(0),
		}
		leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		leafBytes, _ := x509.CreateCertificate(rand.Reader, leafTpl, inter, &leafKey.PublicKey, interKey)
		leaf, _ := x509.ParseCertificate(leafBytes)

		err := verifyCertificates(testRoot, inter, leaf)

		So(err.Error(), ShouldStartWith, "invalid leaf cert Apple extension")
	})

	Convey("Untrusted intermediate certificates are rejected", t, func() {
		interTpl := &x509.Certificate{
			SerialNumber: big.NewInt(0),
			ExtraExtensions: []pkix.Extension{
				{
					Id:    interCertificateOID,
					Value: []byte("test"),
				},
			},
			IsCA:                  true,
			BasicConstraintsValid: true,
		}
		interKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		interBytes, _ := x509.CreateCertificate(rand.Reader, interTpl, interTpl, &interKey.PublicKey, interKey)
		inter, _ := x509.ParseCertificate(interBytes)
		leafTpl := &x509.Certificate{
			SerialNumber: big.NewInt(0),
			ExtraExtensions: []pkix.Extension{
				{
					Id:    leafCertificateOID,
					Value: []byte("test"),
				},
			},
		}
		leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		leafBytes, _ := x509.CreateCertificate(rand.Reader, leafTpl, inter, &leafKey.PublicKey, interKey)
		leaf, _ := x509.ParseCertificate(leafBytes)

		err := verifyCertificates(testRoot, inter, leaf)

		So(err.Error(), ShouldStartWith, "intermediate cert is not trusted by root")
	})

	Convey("Untrusted leaf certificates are rejected", t, func() {
		interTpl := &x509.Certificate{
			SerialNumber: big.NewInt(0),
			ExtraExtensions: []pkix.Extension{
				{
					Id:    interCertificateOID,
					Value: []byte("test"),
				},
			},
			IsCA:                  true,
			BasicConstraintsValid: true,
		}
		interKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		interBytes, _ := x509.CreateCertificate(rand.Reader, interTpl, testRoot, &interKey.PublicKey, rootKey)
		inter, _ := x509.ParseCertificate(interBytes)
		leafTpl := &x509.Certificate{
			SerialNumber: big.NewInt(0),
			ExtraExtensions: []pkix.Extension{
				{
					Id:    leafCertificateOID,
					Value: []byte("test"),
				},
			},
		}
		leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		leafBytes, _ := x509.CreateCertificate(rand.Reader, leafTpl, leafTpl, &leafKey.PublicKey, leafKey)
		leaf, _ := x509.ParseCertificate(leafBytes)

		err := verifyCertificates(testRoot, inter, leaf)

		So(err.Error(), ShouldStartWith, "leaf cert is not trusted by intermediate cert")
	})

	Convey("Properly formed certificate chains are valid", t, func() {
		token := &PKPaymentToken{}
		json.Unmarshal([]byte(`{"transactionIdentifier":"D60E5B29DAAF960C9837D15F1E968E1BB3AD124FE7FA4F85482D7D53789C273F","paymentMethod":{"network":"Visa","type":"debit","displayName":"Visa 3595"},"paymentData":{"version":"EC_v1","header":{"transactionId":"d60e5b29daaf960c9837d15f1e968e1bb3ad124fe7fa4f85482d7d53789c273f","publicKeyHash":"hErQTIkV+XDB8kVuVvYI+1PUv/iIJPuFg2QF/+z1NIo=","ephemeralPublicKey":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEH5hMm7QXtTZBVHqIEg4PZveYt0vkmO1SsIWthxzl8NMBfhtPiUDkvgAKoUAOsTu2WqZxoJqccEX3GwWk4fIEjw=="},"signature":"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","data":"qMvuwnxckj/BzZgR7bR75QqCB+CmEo8AYPJDZl+oD/eZgzcvHB1UfwXdyOIjQk1NX0whfwPZoh6Xfkxvb6g0F9Y/dTtJW4E5aD39NDlaZD5C8XOyDlx27IXCOc5vkEyfV4z1T15wsmYKRl0K+BcmaLbuYEmCQGTwq4Z1LVLhlDpkbtdrqr7WuBH6mIToV4AV+zlTfKj67uLRpmhqBLox14hFkVl3Il15Oq6PnYP2f+padZudUrkjWOPR8pNepPF52EL/mUNadKs3NjqG9uJLl2ELY1A+MESosJ6zoSpKuBBF8FxvaJQgDCJS2yeOut+r8okbh06xVMjNPLC7dGyGW2a6OdpsMGc5+nsP9bs3V6NIosYDCoszEBVFFFjjnYSJhdlER1i6lGE6RTjSUnPGMSb4aknjrDRN/4AJz4Q="}}`), token)
		// parse p7
		p7, err := pkcs7.Parse(token.PaymentData.Signature)
		require.NoError(t, err)
		require.True(t, len(p7.Certificates) >= 2)

		inter, leaf := p7.Certificates[1], p7.Certificates[0]

		err = verifyCertificates(appleRoot, inter, leaf)

		So(err, ShouldBeNil)
	})
}

func TestSignedData(t *testing.T) {
	Convey("EC tokens are processed properly", t, func() {
		token := &PKPaymentToken{
			PaymentData: PaymentData{
				Version: string(vEC_v1),
				Header: Header{
					TransactionID:      "7472616e73616374696f6e5f69642d",
					EphemeralPublicKey: []byte("ephemeral_public_key-"),
					ApplicationData:    "6170706c69636174696f6e5f64617461",
				},
				Data: []byte("data-"),
			},
		}
		res := token.signedData()

		So(res, ShouldResemble, []byte("ephemeral_public_key-data-transaction_id-application_data"))
	})

	Convey("RSA tokens are processed properly", t, func() {
		token := &PKPaymentToken{
			PaymentData: PaymentData{
				Version: string(vRSA_v1),
				Header: Header{
					TransactionID:   "7472616e73616374696f6e5f69642d",
					WrappedKey:      []byte("wrapped_key-"),
					ApplicationData: "6170706c69636174696f6e5f64617461",
				},
				Data: []byte("data-"),
			},
		}
		res := token.signedData()

		So(res, ShouldResemble, []byte("wrapped_key-data-transaction_id-application_data"))
	})
}
