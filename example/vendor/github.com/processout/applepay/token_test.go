package applepay

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
)

func TestPublicKeyHash(t *testing.T) {
	Convey("Failing token signatures are rejected", t, func() {
		invalidSignatureToken := &PKPaymentToken{
			PaymentData: PaymentData{
				Version: string(vEC_v1),
				Header: Header{
					TransactionID: "87451e8280eb80472832b45739ca1722984fae5865957e1c8f4c77a312399c79",
				},
			},
		}
		hash, err := invalidSignatureToken.PublicKeyHash()

		Convey("hash is nil", func() {
			So(hash, ShouldBeNil)
		})

		Convey("err is correct", func() {
			So(err.Error(), ShouldStartWith, "invalid token signature")
		})
	})

	Convey("The hash of the public payment processing key is returned", t, func() {
		t := &PKPaymentToken{}
		json.Unmarshal([]byte(`{"transactionIdentifier":"D60E5B29DAAF960C9837D15F1E968E1BB3AD124FE7FA4F85482D7D53789C273F","paymentMethod":{"network":"Visa","type":"debit","displayName":"Visa 3595"},"paymentData":{"version":"EC_v1","header":{"transactionId":"d60e5b29daaf960c9837d15f1e968e1bb3ad124fe7fa4f85482d7d53789c273f","publicKeyHash":"hErQTIkV+XDB8kVuVvYI+1PUv/iIJPuFg2QF/+z1NIo=","ephemeralPublicKey":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEH5hMm7QXtTZBVHqIEg4PZveYt0vkmO1SsIWthxzl8NMBfhtPiUDkvgAKoUAOsTu2WqZxoJqccEX3GwWk4fIEjw=="},"signature":"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","data":"qMvuwnxckj/BzZgR7bR75QqCB+CmEo8AYPJDZl+oD/eZgzcvHB1UfwXdyOIjQk1NX0whfwPZoh6Xfkxvb6g0F9Y/dTtJW4E5aD39NDlaZD5C8XOyDlx27IXCOc5vkEyfV4z1T15wsmYKRl0K+BcmaLbuYEmCQGTwq4Z1LVLhlDpkbtdrqr7WuBH6mIToV4AV+zlTfKj67uLRpmhqBLox14hFkVl3Il15Oq6PnYP2f+padZudUrkjWOPR8pNepPF52EL/mUNadKs3NjqG9uJLl2ELY1A+MESosJ6zoSpKuBBF8FxvaJQgDCJS2yeOut+r8okbh06xVMjNPLC7dGyGW2a6OdpsMGc5+nsP9bs3V6NIosYDCoszEBVFFFjjnYSJhdlER1i6lGE6RTjSUnPGMSb4aknjrDRN/4AJz4Q="}}`), t)

		hash, err := t.PublicKeyHash()
		expectedHash, _ := base64.StdEncoding.DecodeString("hErQTIkV+XDB8kVuVvYI+1PUv/iIJPuFg2QF/+z1NIo=")

		Convey("hash is correct", func() {
			So(hash, ShouldResemble, expectedHash)
		})

		Convey("err is nil", func() {
			So(err, ShouldBeNil)
		})
	})
}

func TestSetTransactionTime(t *testing.T) {
	Convey("Nil tokens generate an error", t, func() {
		var token *PKPaymentToken
		err := token.SetTransactionTime(time.Now())

		Convey("err is correct", func() {
			So(err.Error(), ShouldEqual, "nil token")
		})
	})

	Convey("SetTransactionTime sets the time correctly", t, func() {
		transactionTime := time.Now()
		token := &PKPaymentToken{}
		err := token.SetTransactionTime(transactionTime)

		Convey("time is correct", func() {
			So(token.transactionTime, ShouldResemble, transactionTime)
		})

		Convey("err is nil", func() {
			So(err, ShouldBeNil)
		})
	})
}

func TestCheckVersion(t *testing.T) {
	Convey("Random strings are not supported", t, func() {
		t := &PKPaymentToken{PaymentData: PaymentData{Version: "XXXXXX"}}
		So(t.checkVersion(), ShouldNotBeNil)
	})

	Convey("EC_v1 is supported", t, func() {
		t := &PKPaymentToken{PaymentData: PaymentData{Version: "EC_v1"}}
		So(t.checkVersion(), ShouldBeNil)
	})

	Convey("RSA_v1 is supported", t, func() {
		t := &PKPaymentToken{PaymentData: PaymentData{Version: "RSA_v1"}}
		So(t.checkVersion(), ShouldBeNil)
	})
}

func TestVersion_String(t *testing.T) {
	Convey("RSA_v1 is correct when converted", t, func() {
		So(vRSA_v1.String(), ShouldEqual, "RSA_v1")
	})

	Convey("EC_v1 is correct when converted", t, func() {
		So(vEC_v1, ShouldEqual, "EC_v1")
	})
}
