# Digest
it's a go implementation for digest auth

### Download
```cmd
go get github.com/telebroad/digest
```

### DEMOS
#### Basic example

```go
package main

import (
	"fmt"
	"github.com/telebroad/digest"
)

var (
	method = "POST"
	host   = "https://www.example.com"
	uri    = "/some/route"
	user   = "my-username"
	pass   = "my-password"
)

func main (){
	token, err := digest.Token(method, host, uri, user, pass)
	if err != nil {
		// handle error
	}

	fmt.Printf("http header token: %s\n",token)
}
```

#### more advance

```go
package main

import (
	"fmt"
	"strings"
	"github.com/telebroad/digest"
)

var (
	method = "POST"
	host   = "https://www.example.com"
	uri    = "/some/route"
	user   = "my-username"
	pass   = "my-password"
)

func main (){
	dig, err := digest.New(method, host, uri, user, pass)
	if err != nil {
		// handle error
	}
	// this will return http request and append the header to it 
	httpClienRequest, err := dig.Request(strings.NewReader("<body>some example body</body>"))
	if err != nil {
		// handle error
	}
	......
}
```