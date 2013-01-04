/*

Package tldextract provides the ability to extract gTLD or ccTLD(generic or country code top-level domain), the registered domain and subdomain from a url according to the Public Suffix List.

A simple usage:
	package main

	import (
		"fmt"
		"github.com/joeguo/tldextract"
	)
	func main() {
		urls := []string{"git+ssh://www.github.com:8443/", "http://media.forums.theregister.co.uk", "http://218.15.32.76", "http://google.com?q=cats"}
		cache := "/tmp/tld.cache"
		extract := tldextract.New(cache,false)

		for _, u := range (urls) {
			result:=extract.Extract(u)
			fmt.Printf("%+v;%s\n",result,u)
		}
    }

*/
package tldextract

