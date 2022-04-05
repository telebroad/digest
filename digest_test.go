package digest

import "testing"

func TestDigest(t *testing.T) {

	var (
		method = "POST"
		host   = "https://www.example.com"
		uri    = "/some/route"
		user   = "my-username"
		pass   = "my-password"
	)

	token, err := Token(method, host, uri, user, pass, false)
	if err != nil {
		t.Errorf("token failed: %s", err.Error())
	}
	t.Logf("results: %s", token)
}
