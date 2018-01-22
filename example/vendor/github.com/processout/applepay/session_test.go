package applepay

import (
	"crypto/tls"
	"net/http"
	"os"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
)

func TestSession(t *testing.T) {
	Convey("Nil merchant certificates are rejected", t, func() {
		m, _ := New("merchant.com.processout.test")
		res, err := m.Session("https://apple-pay-gateway.apple.com/paymentservices/startSession")

		Convey("res should be nil", func() {
			So(res, ShouldBeNil)
		})

		Convey("err should be correct", func() {
			So(err.Error(), ShouldStartWith, "nil merchant certificate")
		})
	})

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
		MerchantDisplayName("example merchant"),
		MerchantDomainName("test.processout.com"),
		MerchantCertificateLocation(
			"tests/certs/cert-merchant.crt",
			"tests/certs/cert-merchant-key.pem",
		),
	)

	Convey("An invalid session URL is blocked", t, func() {
		requestTimeout = 30 * time.Second
		res, err := m.Session("http://example.com")

		Convey("res should be nil", func() {
			So(res, ShouldBeNil)
		})

		Convey("err should be correct", func() {
			So(err.Error(), ShouldStartWith, "invalid session request URL")
		})
	})

	Convey("Request errors are caught", t, func() {
		// Let's see if Apple Pay is that fast!
		requestTimeout = time.Nanosecond

		res, err := m.Session("https://apple-pay-gateway.apple.com/paymentservices/startSession")

		Convey("res should be nil", func() {
			So(res, ShouldBeNil)
		})

		Convey("err should be correct", func() {
			So(err.Error(), ShouldStartWith, "error making the request")
		})
	})

	Convey("A normal request works", t, func() {
		requestTimeout = 30 * time.Second
		res, err := m.Session("https://apple-pay-gateway.apple.com/paymentservices/startSession")

		Convey("The body of the response is returned properly", func() {
			// Out details won't actually work so we'll just check that we're getting some JSON
			So(string(res), ShouldContainSubstring, "{")
		})

		Convey("err is nil", func() {
			So(err, ShouldBeNil)
		})
	})
}

func TestCheckSessionURL(t *testing.T) {
	Convey("Invalid urls", t, func() {
		Convey("An known invalid URL does not work", func() {
			So(checkSessionURL("%gh&%ij"), ShouldNotBeNil)
		})

		Convey(`"not a url" does not work`, func() {
			So(checkSessionURL("not a url"), ShouldNotBeNil)
		})
	})

	Convey("Wrong domain", t, func() {
		Convey("example.com does not work", func() {
			So(checkSessionURL("httos://example.com"), ShouldNotBeNil)
		})

		Convey("apple.com does not work", func() {
			So(checkSessionURL("https://apple.com"), ShouldNotBeNil)
		})
	})

	Convey("Wrong scheme", t, func() {
		Convey("HTTP does not work", func() {
			So(checkSessionURL("http://apple-pay-gateway.apple.com"), ShouldNotBeNil)
		})
	})

	Convey("Valid cases", t, func() {
		Convey("Right domain with right scheme works", func() {
			So(checkSessionURL("https://apple-pay-gateway.apple.com"), ShouldBeNil)
		})

		Convey("Alternative gateway URLs work", func() {
			So(checkSessionURL("https://apple-pay-gateway-cert.apple.com"), ShouldBeNil)
		})

		Convey("Function accepts any path", func() {
			So(checkSessionURL("https://apple-pay-gateway.apple.com/test"), ShouldBeNil)
		})
	})
}

func TestSessionRequest(t *testing.T) {
	Convey("The config should be used", t, func() {
		m := &Merchant{
			identifier:  "merchant.com.example",
			displayName: "example",
			domainName:  "example.com",
		}
		ref := &sessionRequest{
			MerchantIdentifier: "merchant.com.example",
			DomainName:         "example.com",
			DisplayName:        "example",
		}
		res := m.sessionRequest()
		So(res, ShouldResemble, ref)
	})
}

func TestAuthenticatedClient(t *testing.T) {
	Convey("The right certificate is used", t, func() {
		fakeCert := tls.Certificate{Certificate: [][]byte{[]byte("test")}}
		m := &Merchant{merchantCertificate: &fakeCert}

		So(
			m.authenticatedClient().Transport.(*http.Transport).TLSClientConfig.Certificates[0],
			ShouldResemble,
			fakeCert,
		)
	})
}
