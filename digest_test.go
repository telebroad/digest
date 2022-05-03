package digest

import (
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
)

var requestBody = `<?xml version="1.0" encoding="ISO-8859-1"?>
<methodCall>
   <methodName>sample.sum</methodName>
   <params>
      <param>
         <value><int>17</int></value>
      </param>
		 
      <param>
         <value><int>13</int></value>
      </param>
   </params>
</methodCall>
`

type apiData struct {
	method    string
	host      string
	uri       string
	user      string
	pass      string
	userAgent string
}

var theApiData = apiData{
	method:    "POST",
	host:      "https://www.example.com",
	uri:       "/some/route",
	user:      "my-username",
	pass:      "my-password",
	userAgent: "test-user-agent",
}

func TestDigest(t *testing.T) {
	fmt.Printf(">%+v\n", theApiData)
	token, err := Token(theApiData.method, theApiData.host, theApiData.uri, theApiData.user, theApiData.pass, theApiData.userAgent, false)

	if err != nil {
		t.Errorf("token failed: %s", err.Error())
	}
	t.Logf("results: %s", token)
}

func TestRequest(t *testing.T) {
	digest, err := New(theApiData.method, theApiData.host, theApiData.uri, theApiData.user, theApiData.pass, theApiData.userAgent, false)

	if err != nil {
		t.Errorf("token failed: %s", err.Error())
	}

	_, resp, err := digest.RequestAndDo(context.Background(), strings.NewReader(requestBody), false)
	if err != nil {
		return
	}

	t.Logf("Proto: %s", resp.Proto)
	respBody, _ := io.ReadAll(resp.Body)

	t.Logf("status-code: %d\nresults: %s", resp.StatusCode, respBody)
}
