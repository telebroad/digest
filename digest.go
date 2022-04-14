package digest

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type Digest struct {
	method, host, uri, user, pass string
	requireTLS                    bool
	DigestAuth                    string
}

// Token returns digest token header
func Token(method, host, uri, user, pass string, requireTLS bool) (string, error) {
	d, err := New(method, host, uri, user, pass, requireTLS)
	if err != nil {
		return "", err
	}
	return d.DigestAuth, nil
}

// New creates new digest header
func New(method, host, uri, user, pass string, requireTLS bool) (digest *Digest, err error) {
	digest = &Digest{
		method:     method,
		host:       host,
		uri:        uri,
		user:       user,
		pass:       pass,
		requireTLS: requireTLS,
	}

	url := host + uri
	req, err := http.NewRequest(method, url, nil)
	req.Header.Set("Content-Type", "text/xml")

	tr := http.DefaultTransport
	if !requireTLS {
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	client := &http.Client{
		Transport: tr,
	}

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		err = fmt.Errorf("new digest error: recieved status code '%v'", resp.StatusCode)
		return
	}
	digestParts := creatDigestParts(resp)
	digestParts["uri"] = uri
	digestParts["method"] = method
	digestParts["username"] = user
	digestParts["password"] = pass

	digest.DigestAuth = getDigestAuthorization(digestParts)
	return
}

func getDigestAuthorization(digestParts map[string]string) string {
	d := digestParts
	ha1 := getMD5(d["username"] + ":" + d["realm"] + ":" + d["password"])
	ha2 := getMD5(d["method"] + ":" + d["uri"])
	nonceCount := 00000001
	cnonce := getCNonce()
	response := getMD5(fmt.Sprintf("%s:%s:%v:%s:%s:%s", ha1, d["nonce"], nonceCount, cnonce, d["qop"], ha2))
	authorization := fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", cnonce="%s", nc="%v", qop="%s", response="%s"`,
		d["username"], d["realm"], d["nonce"], d["uri"], cnonce, nonceCount, d["qop"], response)
	return authorization
}

func creatDigestParts(resp *http.Response) map[string]string {
	result := map[string]string{}
	if len(resp.Header["Www-Authenticate"]) > 0 {
		wantedHeaders := []string{"nonce", "realm", "qop"}
		responseHeaders := strings.Split(resp.Header["Www-Authenticate"][0], ",")
		for _, r := range responseHeaders {
			for _, w := range wantedHeaders {
				if strings.Contains(r, w) {
					result[w] = strings.Split(r, `"`)[1]
				}
			}
		}
	}
	return result
}

func getMD5(text string) string {
	hash := md5.New()
	hash.Write([]byte(text))
	return hex.EncodeToString(hash.Sum(nil))
}

func getCNonce() string {
	b := make([]byte, 8)
	io.ReadFull(rand.Reader, b)
	return fmt.Sprintf("%x", b)[:16]
}

func (digest *Digest) Request(ctx context.Context, body io.Reader) (req *http.Request, err error) {
	url := digest.host + digest.uri

	if ctx == nil {
		ctx = context.Background()
	}

	req, err = http.NewRequestWithContext(ctx, digest.method, url, body)
	if err != nil {
		err = fmt.Errorf("digest request: %w", err)
		return
	}
	req.Header.Set("Authorization", digest.DigestAuth)
	return
}

func (digest *Digest) RequestAndDo(ctx context.Context, body io.Reader) (req *http.Request, resp *http.Response, err error) {
	req, err = digest.Request(ctx, body)
	if err != nil {
		return
	}

	if ctx != nil {
		req = req.WithContext(ctx)
	}

	tr := http.DefaultTransport

	if !digest.requireTLS {
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	client := &http.Client{
		Transport: tr,
	}

	resp, err = client.Do(req)
	if err != nil {
		err = fmt.Errorf("http do request error: %w", err)
	}
	return
}
