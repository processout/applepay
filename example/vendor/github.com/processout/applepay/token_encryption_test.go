package applepay

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math"
	"math/big"
	"os"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
)

func init() {
	TransactionTimeWindow = time.Duration(math.MaxInt64)
}

func TestDecryptResponse(t *testing.T) {
	if _, err := os.Stat("tests/certs/cert-merchant.crt"); os.IsNotExist(err) {
		t.Skip()
		return
	}
	if _, err := os.Stat("tests/certs/cert-processing.crt"); os.IsNotExist(err) {
		t.Skip()
		return
	}

	m, _ := New(
		"merchant.com.processout.test",
		ProcessingCertificateLocation(
			"tests/certs/cert-processing.crt",
			"tests/certs/cert-processing-key.pem",
		),
	)

	token := &PKPaymentToken{}
	json.Unmarshal([]byte(`{"transactionIdentifier":"D60E5B29DAAF960C9837D15F1E968E1BB3AD124FE7FA4F85482D7D53789C273F","paymentMethod":{"network":"Visa","type":"debit","displayName":"Visa 3595"},"paymentData":{"version":"EC_v1","header":{"transactionId":"d60e5b29daaf960c9837d15f1e968e1bb3ad124fe7fa4f85482d7d53789c273f","publicKeyHash":"hErQTIkV+XDB8kVuVvYI+1PUv/iIJPuFg2QF/+z1NIo=","ephemeralPublicKey":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEH5hMm7QXtTZBVHqIEg4PZveYt0vkmO1SsIWthxzl8NMBfhtPiUDkvgAKoUAOsTu2WqZxoJqccEX3GwWk4fIEjw=="},"signature":"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","data":"qMvuwnxckj/BzZgR7bR75QqCB+CmEo8AYPJDZl+oD/eZgzcvHB1UfwXdyOIjQk1NX0whfwPZoh6Xfkxvb6g0F9Y/dTtJW4E5aD39NDlaZD5C8XOyDlx27IXCOc5vkEyfV4z1T15wsmYKRl0K+BcmaLbuYEmCQGTwq4Z1LVLhlDpkbtdrqr7WuBH6mIToV4AV+zlTfKj67uLRpmhqBLox14hFkVl3Il15Oq6PnYP2f+padZudUrkjWOPR8pNepPF52EL/mUNadKs3NjqG9uJLl2ELY1A+MESosJ6zoSpKuBBF8FxvaJQgDCJS2yeOut+r8okbh06xVMjNPLC7dGyGW2a6OdpsMGc5+nsP9bs3V6NIosYDCoszEBVFFFjjnYSJhdlER1i6lGE6RTjSUnPGMSb4aknjrDRN/4AJz4Q="}}`), token)
	response := &Response{Token: *token}

	Convey("Results are the same as for DecryptToken", t, func() {
		res, err := m.DecryptResponse(response)
		expectedToken := &Token{
			ApplicationPrimaryAccountNumber: "4417083031500965",
			ApplicationExpirationDate:       "221130",
			CurrencyCode:                    "978",
			TransactionAmount:               1,
			DeviceManufacturerIdentifier:    "040010030273",
			PaymentDataType:                 "3DSecure",
			PaymentData: struct {
				OnlinePaymentCryptogram []byte
				ECIIndicator            string
				EMVData                 []byte
				EncryptedPINData        string
			}{
				OnlinePaymentCryptogram: []byte{99, 240, 10, 168, 194, 0, 58, 8, 51, 174, 119, 207, 234, 250, 109, 48, 0, 2, 0, 0},
				ECIIndicator:            "5",
			},
		}

		Convey("token is correct", func() {
			So(res, ShouldResemble, expectedToken)
		})

		Convey("err is nil", func() {
			So(err, ShouldBeNil)
		})
	})
}

func TestDecryptToken(t *testing.T) {
	if _, err := os.Stat("tests/certs/cert-processing-rsa.crt"); os.IsNotExist(err) {
		t.Skip()
		return
	}
	if _, err := os.Stat("tests/certs/cert-processing.crt"); os.IsNotExist(err) {
		t.Skip()
		return
	}

	mEC, _ := New(
		"merchant.com.processout.test",
		ProcessingCertificateLocation(
			"tests/certs/cert-processing.crt",
			"tests/certs/cert-processing-key.pem",
		),
	)
	mRSA, _ := New(
		"merchant.com.processout.test-rsa",
		ProcessingCertificateLocation(
			"tests/certs/cert-processing-rsa.crt",
			"tests/certs/cert-processing-rsa-key.pem",
		),
	)

	ecToken := &PKPaymentToken{}
	json.Unmarshal([]byte(`{"transactionIdentifier":"D60E5B29DAAF960C9837D15F1E968E1BB3AD124FE7FA4F85482D7D53789C273F","paymentMethod":{"network":"Visa","type":"debit","displayName":"Visa 3595"},"paymentData":{"version":"EC_v1","header":{"transactionId":"d60e5b29daaf960c9837d15f1e968e1bb3ad124fe7fa4f85482d7d53789c273f","publicKeyHash":"hErQTIkV+XDB8kVuVvYI+1PUv/iIJPuFg2QF/+z1NIo=","ephemeralPublicKey":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEH5hMm7QXtTZBVHqIEg4PZveYt0vkmO1SsIWthxzl8NMBfhtPiUDkvgAKoUAOsTu2WqZxoJqccEX3GwWk4fIEjw=="},"signature":"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","data":"qMvuwnxckj/BzZgR7bR75QqCB+CmEo8AYPJDZl+oD/eZgzcvHB1UfwXdyOIjQk1NX0whfwPZoh6Xfkxvb6g0F9Y/dTtJW4E5aD39NDlaZD5C8XOyDlx27IXCOc5vkEyfV4z1T15wsmYKRl0K+BcmaLbuYEmCQGTwq4Z1LVLhlDpkbtdrqr7WuBH6mIToV4AV+zlTfKj67uLRpmhqBLox14hFkVl3Il15Oq6PnYP2f+padZudUrkjWOPR8pNepPF52EL/mUNadKs3NjqG9uJLl2ELY1A+MESosJ6zoSpKuBBF8FxvaJQgDCJS2yeOut+r8okbh06xVMjNPLC7dGyGW2a6OdpsMGc5+nsP9bs3V6NIosYDCoszEBVFFFjjnYSJhdlER1i6lGE6RTjSUnPGMSb4aknjrDRN/4AJz4Q="}}`), ecToken)
	rsaToken := &PKPaymentToken{}
	json.Unmarshal([]byte(`{"transactionIdentifier":"87451E8280EB80472832B45739CA1722984FAE5865957E1C8F4C77A312399C79","paymentMethod":{"network":"Visa","type":"debit","displayName":"Visa 3595"},"paymentData":{"version":"RSA_v1","header":{"transactionId":"87451e8280eb80472832b45739ca1722984fae5865957e1c8f4c77a312399c79","publicKeyHash":"+J/p5vUX3+9EE3I/Ds2WioXIFl7klj082vuSQ3vygV0=","wrappedKey":"A6Y4H4Gv9HsQP+UB6lclGiraxCjB3tU/i60On/eTIK2zLvvF+DkrclAgAD0TN+Tpwo5+WB7adRbRYAZ7v15o4RarSg8Up8CWHo+FKcbVTGi0++sjweiP4uCbh6Bp886z8koT6yM+WPq9V505jVeiigA4Ip36GvFgHw3sqHfSIpOjYbeay9yJ9c8lXmasucJjceRjUUS+ZbaYtBYIxii0NvwsMGomztJsFglb2jVpAOt3YXaGIwVr/ss8FBLZdqYAXC+/oz4XcX7zh3cpoNo/qcVnyikdz84WaCBuaWBgRgQGL2ISFrAO531sJK/jkqyZRKzO5DYzXbRFRju7boHCMQ=="},"signature":"MIAGCSqGSIb3DQEHAqCAMIACAQExDzANBglghkgBZQMEAgEFADCABgkqhkiG9w0BBwEAAKCAMIIErTCCBFOgAwIBAgIISaWX1yvjfKIwCgYIKoZIzj0EAwIwejEuMCwGA1UEAwwlQXBwbGUgQXBwbGljYXRpb24gSW50ZWdyYXRpb24gQ0EgLSBHMzEmMCQGA1UECwwdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJBgNVBAYTAlVTMB4XDTE2MDExMTIxMDEyM1oXDTIxMDEwOTIxMDEyM1owXzElMCMGA1UEAwwccnNhLXNtcC1icm9rZXItc2lnbl9VQzQtUFJPRDEUMBIGA1UECwwLaU9TIFN5c3RlbXMxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJBgNVBAYTAlVTMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkQVz1Fhm2yl8s1VuXKa+oUqNn4I0f7cO3syJRN7u7E2QYSa/ZLrN5S/oT62zpPDtxKAIcTr1PbofjhZCCj2cSeyxwFGDKh0qlgn7+6ijDsvELjm3oyq0mxw5ZflxsfXmxCRtuu9mWdUNc/n8vNN1BXtCdeCAqL7MWRZgh/Yrf2MqrozQ7Af8cbo/YTjRwyn/qLngfGOtGBT/BWJ8mVJX295EQ6PguA7fHaDYoCWN6C/BQaeSnxzD+O6YXyOKK1ZbR2IG0YTIP/SQpGbF5/mFdhs3phRS0KCKL2FkwuWIBcUMP2Yo43983tWniEsWFIgwDlAPv7/UEE3ZKjQbJ+o8aQIDAQABo4ICETCCAg0wRQYIKwYBBQUHAQEEOTA3MDUGCCsGAQUFBzABhilodHRwOi8vb2NzcC5hcHBsZS5jb20vb2NzcDA0LWFwcGxlYWljYTMwMzAdBgNVHQ4EFgQUZMOfztomh7HwZGf+qKiURaQ2bCEwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBQj8knET5Pk7yfmxPYobD+iu/0uSzCCAR0GA1UdIASCARQwggEQMIIBDAYJKoZIhvdjZAUBMIH+MIHDBggrBgEFBQcCAjCBtgyBs1JlbGlhbmNlIG9uIHRoaXMgY2VydGlmaWNhdGUgYnkgYW55IHBhcnR5IGFzc3VtZXMgYWNjZXB0YW5jZSBvZiB0aGUgdGhlbiBhcHBsaWNhYmxlIHN0YW5kYXJkIHRlcm1zIGFuZCBjb25kaXRpb25zIG9mIHVzZSwgY2VydGlmaWNhdGUgcG9saWN5IGFuZCBjZXJ0aWZpY2F0aW9uIHByYWN0aWNlIHN0YXRlbWVudHMuMDYGCCsGAQUFBwIBFipodHRwOi8vd3d3LmFwcGxlLmNvbS9jZXJ0aWZpY2F0ZWF1dGhvcml0eS8wNAYDVR0fBC0wKzApoCegJYYjaHR0cDovL2NybC5hcHBsZS5jb20vYXBwbGVhaWNhMy5jcmwwDgYDVR0PAQH/BAQDAgeAMA8GCSqGSIb3Y2QGHQQCBQAwCgYIKoZIzj0EAwIDSAAwRQIgXT37W8PKVeh6RScRafB4pS6ozOJRkPqjl+3V7xZDGIUCIQDTk4hvkbnSjzzhhGxlIHLrAgLTCtxr/k7cw2sWjpSsezCCAu4wggJ1oAMCAQICCEltL786mNqXMAoGCCqGSM49BAMCMGcxGzAZBgNVBAMMEkFwcGxlIFJvb3QgQ0EgLSBHMzEmMCQGA1UECwwdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJBgNVBAYTAlVTMB4XDTE0MDUwNjIzNDYzMFoXDTI5MDUwNjIzNDYzMFowejEuMCwGA1UEAwwlQXBwbGUgQXBwbGljYXRpb24gSW50ZWdyYXRpb24gQ0EgLSBHMzEmMCQGA1UECwwdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJBgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8BcRhBnXZIXVGl4lgQd26ICi7957rk3gjfxLk+EzVtVmWzWuItCXdg0iTnu6CP12F86Iy3a7ZnC+yOgphP9URaOB9zCB9DBGBggrBgEFBQcBAQQ6MDgwNgYIKwYBBQUHMAGGKmh0dHA6Ly9vY3NwLmFwcGxlLmNvbS9vY3NwMDQtYXBwbGVyb290Y2FnMzAdBgNVHQ4EFgQUI/JJxE+T5O8n5sT2KGw/orv9LkswDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBS7sN6hWDOImqSKmd6+veuv2sskqzA3BgNVHR8EMDAuMCygKqAohiZodHRwOi8vY3JsLmFwcGxlLmNvbS9hcHBsZXJvb3RjYWczLmNybDAOBgNVHQ8BAf8EBAMCAQYwEAYKKoZIhvdjZAYCDgQCBQAwCgYIKoZIzj0EAwIDZwAwZAIwOs9yg1EWmbGG+zXDVspiv/QX7dkPdU2ijr7xnIFeQreJ+Jj3m1mfmNVBDY+d6cL+AjAyLdVEIbCjBXdsXfM4O5Bn/Rd8LCFtlk/GcmmCEm9U+Hp9G5nLmwmJIWEGmQ8Jkh0AADGCAk0wggJJAgEBMIGGMHoxLjAsBgNVBAMMJUFwcGxlIEFwcGxpY2F0aW9uIEludGVncmF0aW9uIENBIC0gRzMxJjAkBgNVBAsMHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUwIISaWX1yvjfKIwDQYJYIZIAWUDBAIBBQCggZgwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMTcwMjAxMjE1NjUzWjAtBgkqhkiG9w0BCTQxIDAeMA0GCWCGSAFlAwQCAQUAoQ0GCSqGSIb3DQEBCwUAMC8GCSqGSIb3DQEJBDEiBCCYJuVkRLkXxmaF5AZ6IRNM5D2rrbY0I/bd6mPhB9NA2zANBgkqhkiG9w0BAQsFAASCAQABnFGK+J7tBedpQUfRugkQO4m+coi3RSpyMZ/2z1PLvZLSY+4J9v+q+ZC7tBjSVLvmOcWBdf0qRXr5A6Fn3hIgXlUv6w9QOiju+EgLE2Ci8eLDsnV13w6Gwssmk2kMxExqjAAr48Xs5u4e8HjZfgWiPAMiRLrW4K2AQis++PQkp0AbROIutr88LOs0sbeBsbA0d4w7M3Kd08lh5IPrSHvXntGbJbnzZmY/CQziThizaHIAQPKU1dgHkvycqIeHXNeVmKLPeL1afWJHyEp9IFWgWIqU9m39Jd+TUxmCUX+KwGR+UeAB6JJwwAqsSClPcd1zvnSK3Fp1Qo4nEfhEjyjlAAAAAAAA","data":"yC9NwPNHtejMpAyTkl5k3478E91Acw446q42nc0TfG7DH6E7AnokfXCp0hMjXzeM9uzVHgvAN9f6B+aafIk1AU0QZK1F3+w8Qle8yVUDZwcxQUNBb4dR4u5SPyqYBXu2oAwDggmTzcaXOnh7RDEcTQFBzDz+bBjZ6J+PxtMuqhJ78a97j5mszi3pejB7cqBPDOHiwCM9eUg4YrpPR/A8Sr427aWI8LkPyjGOYxYiVSvFq6Pq1gVRaK7Tm5C6XeVQD3zHHiTeX9kZkyjPilTOnOfouHWHJVZKiZfGDTxhTAse+jC/RxWEibSLRtKOGSTXllCXyPgBItdDj4r+KXE2QqWLPIWUPJSzVihoK78fOoAdhTKLdhM7dLEpvHgUj99lxXsbzPX70lIzHudySWI6F7Dt+vmYPRSK8IcL3qU="}}`), rsaToken)

	Convey("Invalid signatures are rejected", t, func() {
		invalidSignatureToken := &PKPaymentToken{
			PaymentData: PaymentData{
				Version: string(vEC_v1),
				Header: Header{
					TransactionID: "87451e8280eb80472832b45739ca1722984fae5865957e1c8f4c77a312399c79",
				},
			},
		}
		res, err := mEC.DecryptToken(invalidSignatureToken)

		Convey("token is nil", func() {
			So(res, ShouldBeNil)
		})

		Convey("err is correct", func() {
			So(err.Error(), ShouldStartWith, "invalid token signature")
		})
	})

	Convey("Key computation errors are caught", t, func() {
		m2 := &Merchant{
			merchantCertificate:   mEC.merchantCertificate,
			processingCertificate: mEC.merchantCertificate,
		}

		res, err := m2.DecryptToken(ecToken)

		Convey("token is nil", func() {
			So(res, ShouldBeNil)
		})

		Convey("err is correct", func() {
			So(err.Error(), ShouldStartWith, "nil processing certificate")
		})
	})

	Convey("Decryption errors are caught", t, func() {
		m2 := &Merchant{
			merchantCertificate:   mEC.merchantCertificate,
			processingCertificate: mEC.processingCertificate,
		}

		res, err := m2.DecryptToken(ecToken)

		Convey("token is nil", func() {
			So(res, ShouldBeNil)
		})

		Convey("err is correct", func() {
			So(err.Error(), ShouldStartWith, "error decrypting the token")
		})
	})

	Convey("Valid EC tokens are decrypted properly", t, func() {
		res, err := mEC.DecryptToken(ecToken)
		expectedToken := &Token{
			ApplicationPrimaryAccountNumber: "4417083031500965",
			ApplicationExpirationDate:       "221130",
			CurrencyCode:                    "978",
			TransactionAmount:               1,
			DeviceManufacturerIdentifier:    "040010030273",
			PaymentDataType:                 "3DSecure",
			PaymentData: struct {
				OnlinePaymentCryptogram []byte
				ECIIndicator            string
				EMVData                 []byte
				EncryptedPINData        string
			}{
				OnlinePaymentCryptogram: []byte{99, 240, 10, 168, 194, 0, 58, 8, 51, 174, 119, 207, 234, 250, 109, 48, 0, 2, 0, 0},
				ECIIndicator:            "5",
			},
		}

		Convey("token is correct", func() {
			So(res, ShouldResemble, expectedToken)
		})

		Convey("err is nil", func() {
			So(err, ShouldBeNil)
		})
	})

	Convey("Valid RSA tokens are decrypted properly", t, func() {
		res, err := mRSA.DecryptToken(rsaToken)
		expectedToken := &Token{
			ApplicationPrimaryAccountNumber: "4417083031500965",
			ApplicationExpirationDate:       "221130",
			CurrencyCode:                    "978",
			TransactionAmount:               1,
			DeviceManufacturerIdentifier:    "040010030273",
			PaymentDataType:                 "3DSecure",
			PaymentData: struct {
				OnlinePaymentCryptogram []byte
				ECIIndicator            string
				EMVData                 []byte
				EncryptedPINData        string
			}{
				OnlinePaymentCryptogram: []byte{99, 52, 248, 159, 106, 0, 59, 176, 216, 2, 70, 44, 90, 197, 185, 48, 0, 2, 0, 0},
				ECIIndicator:            "5",
			},
		}

		Convey("token is correct", func() {
			So(res, ShouldResemble, expectedToken)
		})

		Convey("err is nil", func() {
			So(err, ShouldBeNil)
		})
	})
}

func TestComputeEncryptionKey(t *testing.T) {
	if _, err := os.Stat("tests/certs/cert-merchant.crt"); os.IsNotExist(err) {
		t.Skip()
		return
	}
	if _, err := os.Stat("tests/certs/cert-processing.crt"); os.IsNotExist(err) {
		t.Skip()
		return
	}

	m, _ := New(
		"merchant.com.processout.test",
		ProcessingCertificateLocation(
			"tests/certs/cert-processing.crt",
			"tests/certs/cert-processing-key.pem",
		),
	)

	Convey("Invalid epehemeral public keys result in an error", t, func() {
		t := &PKPaymentToken{}
		t.PaymentData.Header.EphemeralPublicKey = []byte{}

		key, err := m.computeEncryptionKey(t)

		Convey("key is nil", func() {
			So(key, ShouldBeNil)
		})

		Convey("err is correct", func() {
			So(err.Error(), ShouldStartWith, "unable to parse the public key")
		})
	})

	Convey("Non-elliptic processing keys are rejected", t, func() {
		m2 := &Merchant{
			merchantCertificate: m.merchantCertificate,
		}
		tpl := &x509.Certificate{SerialNumber: big.NewInt(0)}
		mKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		mCertB, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &mKey.PublicKey, mKey)
		m2.processingCertificate = &tls.Certificate{
			Certificate: [][]byte{mCertB},
		}

		t := &PKPaymentToken{}
		t.PaymentData.Header.EphemeralPublicKey, _ = base64.StdEncoding.DecodeString("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEH5hMm7QXtTZBVHqIEg4PZveYt0vkmO1SsIWthxzl8NMBfhtPiUDkvgAKoUAOsTu2WqZxoJqccEX3GwWk4fIEjw==")

		key, err := m2.computeEncryptionKey(t)

		Convey("key is nil", func() {
			So(key, ShouldBeNil)
		})

		Convey("err is correct", func() {
			So(err.Error(), ShouldEqual, "non-elliptic processing private key")
		})
	})

	Convey("Encryption key is computed properly with correct parameters", t, func() {
		t := &PKPaymentToken{}
		t.PaymentData.Header.EphemeralPublicKey, _ = base64.StdEncoding.DecodeString("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEH5hMm7QXtTZBVHqIEg4PZveYt0vkmO1SsIWthxzl8NMBfhtPiUDkvgAKoUAOsTu2WqZxoJqccEX3GwWk4fIEjw==")

		key, err := m.computeEncryptionKey(t)

		Convey("key is correct", func() {
			So(key, ShouldResemble, []byte{10, 130, 215, 130, 147, 201, 145, 236, 211, 219, 140, 70, 140, 203, 236, 23, 105, 85, 123, 243, 184, 255, 101, 171, 112, 2, 191, 86, 112, 139, 154, 187})
		})

		Convey("err is nil", func() {
			So(err, ShouldBeNil)
		})
	})
}

func TestEphemeralPublicKey(t *testing.T) {
	Convey("Invalid key", t, func() {
		t := &PKPaymentToken{
			PaymentData: PaymentData{
				Header: Header{
					EphemeralPublicKey: []byte("obviously not a key"),
				},
			},
		}
		pub, err := t.ephemeralPublicKey()
		Convey("Public key should be nil", func() {
			So(pub, ShouldBeNil)
		})
		Convey("Error should not be nil", func() {
			So(err, ShouldNotBeNil)
		})
	})

	Convey("RSA key", t, func() {
		key, _ := base64.StdEncoding.DecodeString("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Jeh+BjAxKfPtzI/qN2YSHag0NXgZl6F7E+p3HNknYneVNfiqRlqjoO1nW1u72nmCPQuyrT3AXd6npqBABTLsadMQoEwU2dzgLI94KRU1bAhZ3gij+ibfxJvRW22YXnD4KaBmC3LDhB2AZWiEQgN9GEuWQo1G/T77F0+Y1ww0wxGNYdud7LYEi5inGQwydizbcGrJPhnZ4LZx7cSZ3BZzX23ckJZ9vTQHpHGEzNAKLUzQpST0L0xUsugkjcjZNYoAgKo0TrR8yJ7FykAD5rVzQShVLsoP///36eiZQjVXsr988lhAEqtdC6GCR70WwlP5mHLBarWG1BODiqflMLOeQIDAQAB")
		t := &PKPaymentToken{
			PaymentData: PaymentData{
				Header: Header{
					EphemeralPublicKey: key,
				},
			},
		}
		pub, err := t.ephemeralPublicKey()
		Convey("Public key should be nil", func() {
			So(pub, ShouldBeNil)
		})
		Convey("Error should not be nil", func() {
			So(err, ShouldNotBeNil)
		})

	})

	Convey("Valid key", t, func() {
		key, _ := base64.StdEncoding.DecodeString("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqTV0E3dFQ2fg9QbIQ1a8sGMHav6UicUjo5nyWnO4kBAWxOGTUauID6L48yjKSk6nJDJU6pYNZXDyTyHalW+zjA==")
		t := &PKPaymentToken{
			PaymentData: PaymentData{
				Header: Header{
					EphemeralPublicKey: key,
				},
			},
		}
		pub, err := t.ephemeralPublicKey()
		Convey("Public key should be nil", func() {
			So(pub, ShouldNotBeNil)
		})
		Convey("Error should not be nil", func() {
			So(err, ShouldBeNil)
		})
	})
}

func TestECDHESharedSecret(t *testing.T) {
	Convey("Generic test", t, func() {
		So(
			ecdheSharedSecret(
				&ecdsa.PublicKey{
					X: big.NewInt(3),
					Y: big.NewInt(2),
				},
				&ecdsa.PrivateKey{
					PublicKey: ecdsa.PublicKey{
						Curve: elliptic.P256(),
					},
					D: big.NewInt(2),
				},
			),
			ShouldResemble,
			big.NewInt(30),
		)
	})
}

func TestDeriveEncryptionKey(t *testing.T) {
	Convey("Arbitrary numbers should give a correct result", t, func() {
		So(
			hex.EncodeToString(
				deriveEncryptionKey(big.NewInt(0), []byte{0}),
			),
			ShouldEqual,
			"b50fb7efdb1ce4b7036e9dc0531ebb9d0101c4bcc57aba5a9f3c39fb5cdfafa6",
		)
	})
}

func TestUnwrapEncryptionKey(t *testing.T) {
	if _, err := os.Stat("tests/certs/cert-processing-rsa.crt"); os.IsNotExist(err) {
		t.Skip()
		return
	}
	if _, err := os.Stat("tests/certs/cert-processing.crt"); os.IsNotExist(err) {
		t.Skip()
		return
	}

	m, _ := New(
		"merchant.com.processout.test-rsa",
		ProcessingCertificateLocation(
			"tests/certs/cert-processing-rsa.crt",
			"tests/certs/cert-processing-rsa-key.pem",
		),
	)

	token := &PKPaymentToken{}
	token.PaymentData.Header.WrappedKey, _ = base64.StdEncoding.DecodeString("A6Y4H4Gv9HsQP+UB6lclGiraxCjB3tU/i60On/eTIK2zLvvF+DkrclAgAD0TN+Tpwo5+WB7adRbRYAZ7v15o4RarSg8Up8CWHo+FKcbVTGi0++sjweiP4uCbh6Bp886z8koT6yM+WPq9V505jVeiigA4Ip36GvFgHw3sqHfSIpOjYbeay9yJ9c8lXmasucJjceRjUUS+ZbaYtBYIxii0NvwsMGomztJsFglb2jVpAOt3YXaGIwVr/ss8FBLZdqYAXC+/oz4XcX7zh3cpoNo/qcVnyikdz84WaCBuaWBgRgQGL2ISFrAO531sJK/jkqyZRKzO5DYzXbRFRju7boHCMQ==")

	Convey("Non-RSA private key does not work", t, func() {
		m2 := &Merchant{
			merchantCertificate: m.merchantCertificate,
		}
		processingCertificate, _ := tls.LoadX509KeyPair(
			"tests/certs/cert-processing.crt",
			"tests/certs/cert-processing-key.pem",
		)
		m2.processingCertificate = &processingCertificate

		res, err := m2.unwrapEncryptionKey(token)

		Convey("key is nil", func() {
			So(res, ShouldBeNil)
		})

		Convey("err is correct", func() {
			So(err.Error(), ShouldStartWith, "processing key is not RSA")
		})
	})

	Convey("Empty ciphertext is rejected", t, func() {
		token2 := &PKPaymentToken{}
		res, err := m.unwrapEncryptionKey(token2)

		Convey("key is nil", func() {
			So(res, ShouldBeNil)
		})

		Convey("err is correct", func() {
			So(err.Error(), ShouldStartWith, "empty key ciphertext")
		})
	})

	Convey("Invalid ciphertext is rejected", t, func() {
		token2 := &PKPaymentToken{
			PaymentData: PaymentData{
				Header: Header{
					WrappedKey: []byte("invalid ciphertext"),
				},
			},
		}
		res, err := m.unwrapEncryptionKey(token2)

		Convey("key is nil", func() {
			So(res, ShouldBeNil)
		})

		Convey("err is correct", func() {
			So(err.Error(), ShouldStartWith, "error decrypting the key")
		})
	})

	Convey("Correct parameters result in a correctly unwrapped key", t, func() {
		res, err := m.unwrapEncryptionKey(token)
		expectedKey := []byte{218, 13, 57, 122, 254, 44, 223, 66, 71, 49, 130, 77, 249, 104, 7, 236}

		Convey("key is correct", func() {
			So(res, ShouldResemble, expectedKey)
		})

		Convey("err is nil", func() {
			So(err, ShouldBeNil)
		})
	})
}

func TestDecrypt(t *testing.T) {
	ecKey := []byte{10, 130, 215, 130, 147, 201, 145, 236, 211, 219, 140, 70, 140, 203, 236, 23, 105, 85, 123, 243, 184, 255, 101, 171, 112, 2, 191, 86, 112, 139, 154, 187}
	rsaKey := []byte{218, 13, 57, 122, 254, 44, 223, 66, 71, 49, 130, 77, 249, 104, 7, 236}

	ecToken := &PKPaymentToken{}
	ecToken.PaymentData.Data, _ = base64.StdEncoding.DecodeString("qMvuwnxckj/BzZgR7bR75QqCB+CmEo8AYPJDZl+oD/eZgzcvHB1UfwXdyOIjQk1NX0whfwPZoh6Xfkxvb6g0F9Y/dTtJW4E5aD39NDlaZD5C8XOyDlx27IXCOc5vkEyfV4z1T15wsmYKRl0K+BcmaLbuYEmCQGTwq4Z1LVLhlDpkbtdrqr7WuBH6mIToV4AV+zlTfKj67uLRpmhqBLox14hFkVl3Il15Oq6PnYP2f+padZudUrkjWOPR8pNepPF52EL/mUNadKs3NjqG9uJLl2ELY1A+MESosJ6zoSpKuBBF8FxvaJQgDCJS2yeOut+r8okbh06xVMjNPLC7dGyGW2a6OdpsMGc5+nsP9bs3V6NIosYDCoszEBVFFFjjnYSJhdlER1i6lGE6RTjSUnPGMSb4aknjrDRN/4AJz4Q=")
	rsaToken := &PKPaymentToken{}
	rsaToken.PaymentData.Data, _ = base64.StdEncoding.DecodeString("yC9NwPNHtejMpAyTkl5k3478E91Acw446q42nc0TfG7DH6E7AnokfXCp0hMjXzeM9uzVHgvAN9f6B+aafIk1AU0QZK1F3+w8Qle8yVUDZwcxQUNBb4dR4u5SPyqYBXu2oAwDggmTzcaXOnh7RDEcTQFBzDz+bBjZ6J+PxtMuqhJ78a97j5mszi3pejB7cqBPDOHiwCM9eUg4YrpPR/A8Sr427aWI8LkPyjGOYxYiVSvFq6Pq1gVRaK7Tm5C6XeVQD3zHHiTeX9kZkyjPilTOnOfouHWHJVZKiZfGDTxhTAse+jC/RxWEibSLRtKOGSTXllCXyPgBItdDj4r+KXE2QqWLPIWUPJSzVihoK78fOoAdhTKLdhM7dLEpvHgUj99lxXsbzPX70lIzHudySWI6F7Dt+vmYPRSK8IcL3qU=")

	Convey("Wrong key sizes are rejected", t, func() {
		res, err := ecToken.decrypt([]byte("invalid key length"))

		Convey("token is nil", func() {
			So(res, ShouldBeNil)
		})

		Convey("err is correct", func() {
			So(err.Error(), ShouldStartWith, "error creating the block cipher")
		})
	})

	Convey("Invalid ciphertext cannot be opened", t, func() {
		token2 := &PKPaymentToken{PaymentData: PaymentData{Data: []byte("000000000000000000000000")}}
		res, err := token2.decrypt(ecKey)

		Convey("token is nil", func() {
			So(res, ShouldBeNil)
		})

		Convey("err is correct", func() {
			So(err.Error(), ShouldStartWith, "error decrypting the data")
		})
	})

	Convey("Correct EC parameters result in a valid decrypted token", t, func() {
		res, err := ecToken.decrypt(ecKey)

		Convey("token is correct", func() {
			So(string(res), ShouldContainSubstring, "applicationPrimaryAccountNumber")
		})

		Convey("err is nil", func() {
			So(err, ShouldBeNil)
		})
	})

	Convey("Correct RSA parameters result in a valid decrypted token", t, func() {
		res, err := rsaToken.decrypt(rsaKey)

		Convey("token is correct", func() {
			So(string(res), ShouldContainSubstring, "applicationPrimaryAccountNumber")
		})

		Convey("err is nil", func() {
			So(err, ShouldBeNil)
		})
	})
}
