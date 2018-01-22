package applepay

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"time"

	"github.com/pkg/errors"
)

type (
	// sessionRequest is the JSON payload sent to Apple for Apple Pay
	// session requests
	sessionRequest struct {
		MerchantIdentifier string `json:"merchantIdentifier"`
		DomainName         string `json:"domainName"`
		DisplayName        string `json:"displayName"`
	}
)

var (
	requestTimeout = 30 * time.Second
)

// Session returns an opaque payload for setting up an Apple Pay session
func (m Merchant) Session(url string) (sessionPayload []byte, err error) {
	if m.merchantCertificate == nil {
		return nil, errors.New("nil merchant certificate")
	}
	// Verify that the session URL is Apple's
	if err := checkSessionURL(url); err != nil {
		return nil, errors.Wrap(err, "invalid session request URL")
	}

	// Send a session request to Apple
	cl := m.authenticatedClient()
	buf := bytes.NewBuffer(nil)
	json.NewEncoder(buf).Encode(m.sessionRequest())
	res, err := cl.Post(url, "application/json", buf)
	if err != nil {
		return nil, errors.Wrap(err, "error making the request")
	}

	// Return directly the result
	body, _ := ioutil.ReadAll(res.Body)
	//res.Body.Close()
	return body, nil
}

// checkSessionURL validates the request URL sent by the client to check that it
// belongs to Apple
func checkSessionURL(location string) error {
	u, err := url.Parse(location)
	if err != nil {
		return errors.Wrap(err, "error parsing the URL")
	}
	hostReg := regexp.MustCompile("^apple-pay-gateway(-.+)?.apple.com$")
	if !hostReg.MatchString(u.Host) {
		return errors.New("invalid host")
	}
	if u.Scheme != "https" {
		return errors.New("unsupported protocol")
	}
	return nil
}

// sessionRequest builds a request struct for Apple Pay sessions
func (m Merchant) sessionRequest() *sessionRequest {
	return &sessionRequest{
		MerchantIdentifier: m.identifier,
		DomainName:         m.domainName,
		DisplayName:        m.displayName,
	}
}

// authenticatedClient returns a HTTP client authenticated with the Merchant
// Identity certificate signed by Apple
func (m Merchant) authenticatedClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{
					*m.merchantCertificate,
				},
			},
		},
		Timeout: requestTimeout,
	}
}
