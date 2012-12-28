tldextract
==========

Extract root domain, subdomain name, tld from a url, using the Public Suffix List.

Installation
==========
Install tldextract:
```sh
go get github.com/joeguo/tldextract

```
To run unit tests, run this command  in tldextract's source directory($GOPATH/src/github.com/joeguo/tldextract):

```sh
go test
```

Example
==========
```go
package main

import (
	"fmt"
	"github.com/joeguo/tldextract"
)
func main() {
	urls := []string{"git+ssh://www.github.com:8443/", "http://media.forums.theregister.co.uk", "http://258.15.32.876", "http://google.com?q=cats"}
	cache := "/home/joe/dev/go/tldextract/tld.cache"
	extract := tldextract.New(cache,false)

	for _, u := range (urls) {
			result:=extract.Extract(u)
			fmt.Printf("%+v;%s\n",result,u)
	}
}

```