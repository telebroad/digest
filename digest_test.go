package digest

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
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

	_, resp, err := digest.RequestAndDo(context.Background(), bytes.NewBufferString(requestBody), false)
	if err != nil {
		return
	}

	t.Logf("Proto: %s", resp.Proto)
	respBody, _ := io.ReadAll(resp.Body)

	t.Logf("status-code: %d\nresults: %s", resp.StatusCode, respBody)
}

func TestMultipleRequest(t *testing.T) {
	digest, err := New(theApiData.method, theApiData.host, theApiData.uri, theApiData.user, theApiData.pass, theApiData.userAgent, false)

	if err != nil {
		t.Errorf("token failed: %s", err.Error())
	}
	for i := 0; i < 15; i++ {
		reqBody := bytes.NewBufferString(requestBody)
		req, resp, err := digest.RequestAndDo(context.Background(), reqBody, true)
		fmt.Println(time.Now().Format(time.RFC850))
		t.Logf("url: %s", req.URL.String())
		t.Logf("user-agent: %s", req.UserAgent())
		t.Logf("Authorization: %s", req.Header.Get("Authorization"))
		t.Logf("req-body: %s...", strings.Join(strings.SplitN(requestBody, "\n", -1), ""))
		respBody, _ := io.ReadAll(resp.Body)
		t.Logf("status-code: %d", resp.StatusCode)
		t.Logf("res-body: %s...", strings.Join(strings.SplitN(string(respBody), "\n", -1), ""))
		t.Logf("Proto: %s", resp.Proto)
		if err != nil {
			t.Logf("error: %s\n\n", err.Error())
		} else {
			t.Logf("error: nil\n\n")
		}
		<-time.After(time.Second)
	}
}
