tldextract
==========

Extract root domain, subdomain name, tld from a url, using the [the Public Suffix List](http://www.publicsuffix.org).

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
	urls := []string{"git+ssh://www.github.com:8443/", "http://media.forums.theregister.co.uk", "http://218.15.32.76", "http://google.com?q=cats"}
	cache := "/tmp/tld.cache"
	extract, _ := tldextract.New(cache,false)

	for _, u := range (urls) {
		result:=extract.Extract(u)
		fmt.Printf("%+v;%s\n",result,u)
	}
}

```
Output will look like:
```plain
  &{Flag:1 Sub:www Root:github Tld:com};git+ssh://www.github.com:8443/
  &{Flag:1 Sub:media.forums Root:theregister Tld:co.uk};http://media.forums.theregister.co.uk
  &{Flag:2 Sub: Root:218.15.32.76 Tld:};http://218.15.32.76
  &{Flag:1 Sub: Root:google Tld:com};http://google.com?q=cats
```
Flag value meaning
```go
const (
	Malformed = iota
	Domain
	Ip4
	Ip6
)
```

========
