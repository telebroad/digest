package digest

import (
	"fmt"
	"testing"
)

type vars struct {
	method string
	host   string
	uri    string
	user   string
	pass   string
}

var theVars = vars{
	method: "POST",
	host:   "https://www.example.com",
	uri:    "/some/route",
	user:   "my-username",
	pass:   "my-password",
}

func TestDigest(t *testing.T) {
	fmt.Printf(">%+v\n", theVars)
	token, err := Token(theVars.method, theVars.host, theVars.uri, theVars.user, theVars.pass, false)

	if err != nil {
		t.Errorf("token failed: %s", err.Error())
	}
	t.Logf("results: %s", token)
}
