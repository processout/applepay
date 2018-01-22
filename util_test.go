package applepay

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestExtractMerchantHash(t *testing.T) {
	Convey("Nil certificates are rejected", t, func() {
		hash, err := extractMerchantHash(tls.Certificate{})

		Convey("hash should be nil", func() {
			So(hash, ShouldBeNil)
		})

		Convey("err should be correct", func() {
			So(err.Error(), ShouldEqual, "nil certificate")
		})
	})

	Convey("Invalid certificates are rejected", t, func() {
		cert := tls.Certificate{
			Certificate: [][]byte{
				[]byte("not a valid certificate"),
			},
		}
		hash, err := extractMerchantHash(cert)

		Convey("hash should be nil", func() {
			So(hash, ShouldBeNil)
		})

		Convey("err should be correct", func() {
			So(err.Error(), ShouldStartWith, "certificate parsing error")
		})
	})

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	Convey("Certificates without the extension return an error", t, func() {
		tpl := &x509.Certificate{
			SerialNumber: big.NewInt(0),
		}
		cert, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
		hash, err := extractMerchantHash(tls.Certificate{Certificate: [][]byte{cert}})

		Convey("hash should be nil", func() {
			So(hash, ShouldBeNil)
		})

		Convey("err should be correct", func() {
			So(err.Error(), ShouldStartWith, "error finding the hash extension")
		})
	})

	Convey("Certificates with an hash too short return an error", t, func() {
		tpl := &x509.Certificate{
			SerialNumber: big.NewInt(0),
			ExtraExtensions: []pkix.Extension{
				{
					Id:    merchantIDHashOID,
					Value: []byte("@.hash too short"),
				},
			},
		}
		cert, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
		hash, err := extractMerchantHash(tls.Certificate{Certificate: [][]byte{cert}})

		Convey("hash should be nil", func() {
			So(hash, ShouldBeNil)
		})

		Convey("err should be correct", func() {
			So(err.Error(), ShouldEqual, "invalid hash length")
		})
	})

	Convey("Certificates with an invalid hexadecimal hash return an error", t, func() {
		tpl := &x509.Certificate{
			SerialNumber: big.NewInt(0),
			ExtraExtensions: []pkix.Extension{
				{
					Id:    merchantIDHashOID,
					Value: []byte("@.this string is the correct length but it's not valid hexadecimal"),
				},
			},
		}
		cert, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
		hash, err := extractMerchantHash(tls.Certificate{Certificate: [][]byte{cert}})

		Convey("hash should be nil", func() {
			So(hash, ShouldBeNil)
		})

		Convey("err should be correct", func() {
			So(err.Error(), ShouldStartWith, "invalid hash hex")
		})
	})

	Convey("Certificates with a correctly encoded hash return the right value", t, func() {
		tpl := &x509.Certificate{
			SerialNumber: big.NewInt(0),
			ExtraExtensions: []pkix.Extension{
				{
					Id:    merchantIDHashOID,
					Value: []byte("@.cc7614e23cd0e6b5b758c7519977a73624dc4395eb19c3fdb6dcdfbb47158cfd"),
				},
			},
		}
		cert, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
		hash, err := extractMerchantHash(tls.Certificate{Certificate: [][]byte{cert}})

		Convey("hash should be correct", func() {
			expectedHash, _ := hex.DecodeString("cc7614e23cd0e6b5b758c7519977a73624dc4395eb19c3fdb6dcdfbb47158cfd")
			So(hash, ShouldResemble, expectedHash)
		})

		Convey("err should be nil", func() {
			So(err, ShouldBeNil)
		})
	})
}

func TestExtractExtension(t *testing.T) {
	Convey("Nil certificates return an error", t, func() {
		res, err := extractExtension(nil, merchantIDHashOID)

		Convey("value is nil", func() {
			So(res, ShouldBeNil)
		})

		Convey("err is correct", func() {
			So(err.Error(), ShouldEqual, "nil certificate")
		})
	})

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	Convey("Inexisting extensions return an error", t, func() {
		tpl := &x509.Certificate{
			SerialNumber: big.NewInt(0),
			ExtraExtensions: []pkix.Extension{
				{
					Id:    mustParseASN1ObjectIdentifier("1.2.3.4.5"),
					Value: []byte("@.test"),
				}, {
					Id:    mustParseASN1ObjectIdentifier("1.2.3.4.6"),
					Value: []byte("@.test2"),
				},
			},
		}
		certBytes, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
		cert, _ := x509.ParseCertificate(certBytes)
		res, err := extractExtension(cert, merchantIDHashOID)

		Convey("value is nil", func() {
			So(res, ShouldBeNil)
		})

		Convey("err is correct", func() {
			So(err.Error(), ShouldEqual, "extension not found")
		})
	})

	Convey("Valid extensions work", t, func() {
		tpl := &x509.Certificate{
			SerialNumber: big.NewInt(0),
			ExtraExtensions: []pkix.Extension{
				{
					Id:    mustParseASN1ObjectIdentifier("1.2.3.4.5"),
					Value: []byte("@.test"),
				}, {
					Id:    merchantIDHashOID,
					Value: []byte("@.correct value"),
				},
			},
		}
		certBytes, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
		cert, _ := x509.ParseCertificate(certBytes)
		res, err := extractExtension(cert, merchantIDHashOID)

		Convey("value is correct", func() {
			So(res, ShouldResemble, []byte("@.correct value"))
		})

		Convey("err is nil", func() {
			So(err, ShouldBeNil)
		})
	})
}

func TestMustParseASN1ObjectIdentifier(t *testing.T) {
	Convey("Invalid OIDs panic", t, func() {
		var oid asn1.ObjectIdentifier
		recovered := false
		func() {
			defer func() {
				if r := recover(); r != nil {
					recovered = true
				}
			}()
			oid = mustParseASN1ObjectIdentifier("1.2.3.invalid")
		}()
		Convey("panic recovered", func() {
			So(recovered, ShouldBeTrue)
		})
		Convey("oid is nil", func() {
			So(oid, ShouldBeNil)
		})
	})

	Convey("Valid OIDs do not panic", t, func() {
		var oid asn1.ObjectIdentifier
		recovered := false
		func() {
			defer func() {
				if r := recover(); r != nil {
					recovered = true
				}
			}()
			oid = mustParseASN1ObjectIdentifier("1.2.840.113635.100.6.32")
		}()
		Convey("no panic recovered", func() {
			So(recovered, ShouldBeFalse)
		})
		Convey("oid is correct", func() {
			So(oid, ShouldResemble, asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 32})
		})
	})
}

func TestParseASN1ObjectIdentifier(t *testing.T) {
	Convey("Invalid OIDs are not parsed", t, func() {
		oid, err := parseASN1ObjectIdentifier("1.2.3.invalid")

		Convey("oid is nil", func() {
			So(oid, ShouldBeNil)
		})

		Convey("err is not nil", func() {
			So(err, ShouldNotBeNil)
		})
	})

	Convey("Valid OIDs are parsed correctly", t, func() {
		oid, err := parseASN1ObjectIdentifier("1.2.840.113635.100.6.32")

		Convey("oid is correct", func() {
			So(oid, ShouldResemble, asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 32})
		})

		Convey("err is nil", func() {
			So(err, ShouldBeNil)
		})
	})
}
