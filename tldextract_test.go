package tldextract

import (
	"fmt"
	"log"
	"testing"
)

var (
	cache      = "/tmp/tld.cache"
	tldExtract *TLDExtract
	err        error
)

func init() {
	tldExtract, err = New(cache, true)
	if err != nil {
		log.Fatal(err)
	}
}

func assert(url string, expected *Result, returned *Result, t *testing.T) {
	if (expected.Flag == returned.Flag) && (expected.Root == returned.Root) && (expected.Sub == returned.Sub) && (expected.Tld == returned.Tld) {
		return
	}
	t.Errorf("%s;expected:%+v;returned:%+v", url, expected, returned)
}
func aTestA(t *testing.T) {
	result := tldExtract.Extract("9down.cc.html&amp;sa=u&amp;ei=4sfsul-ximsb4ateiicaag&amp;ved=0cbkqfjac&amp;usg=afqjcnfmetjm8-gpgyszv9l1h6_5p369yg/wp-content/themes/airfolio/scripts/timthumb.php")
	fmt.Println(result)
}

func TestAll(t *testing.T) {
	cases := map[string]*Result{"http://www.google.com": &Result{Flag: Domain, Sub: "www", Root: "google", Tld: "com"},
		"https://www.google.com.hk/url?sa=t&rct=j&q=&esrc=s&source=web&cd=1&cad=rja&ved=0CDQQFjAA&url=%68%74%74%70%3a%2f%2f%67%72%6f%75%70%73%2e%67%6f%6f%67%6c%65%2e%63%6f%6d%2f%67%72%6f%75%70%2f%67%6f%6c%61%6e%67%2d%6e%75%74%73%2f%62%72%6f%77%73%65%5f%74%68%72%65%61%64%2f%74%68%72%65%61%64%2f%62%31%61%36%65%31%66%38%37%30%32%62%33%31%31%62&ei=okjQULibA9GYiAfk3IDYDw&usg=AFQjCNFVxgAwHXnmEJWVURboSTiygUMTaQ&sig2=3AIxkh4TR5QYWGXCJtBSZg": &Result{Flag: Domain, Sub: "www", Root: "google", Tld: "com.hk"},
		"http://joe.blogspot.co.uk":                       &Result{Flag: Domain, Sub: "", Root: "joe", Tld: "blogspot.co.uk"},
		"ftp://johndoe:5cr1p7k1dd13@1337.warez.com:2501/": &Result{Flag: Domain, Sub: "1337", Root: "warez", Tld: "com"},
		"git+ssh://www.github.com:8443/":                  &Result{Flag: Domain, Sub: "www", Root: "github", Tld: "com"},
		"http://www.!github.com:8443/":                    &Result{Flag: Malformed},
		"http://www.theregister.co.uk":                    &Result{Flag: Domain, Sub: "www", Root: "theregister", Tld: "co.uk"},
		"http://media.forums.theregister.co.uk":           &Result{Flag: Domain, Sub: "media.forums", Root: "theregister", Tld: "co.uk"},
		"192.168.0.103":                                   &Result{Flag: Ip4, Root: "192.168.0.103"},
		"http://192.168.0.103":                            &Result{Flag: Ip4, Root: "192.168.0.103"},
		"http://216.22.project.coop/":                     &Result{Flag: Domain, Sub: "216.22", Root: "project", Tld: "coop"},
		"http://Gmail.org/":                               &Result{Flag: Domain, Root: "gmail", Tld: "org"},
		"http://wiki.info/":                               &Result{Flag: Domain, Root: "wiki", Tld: "info"},
		"http://wiki.information/":                        &Result{Flag: Malformed},
		"http://wiki/":                                    &Result{Flag: Malformed},
		"http://258.15.32.876":                            &Result{Flag: Malformed},
		"http://www.cgs.act.edu.au/":                      &Result{Flag: Domain, Sub: "www", Root: "cgs", Tld: "act.edu.au"},
		"http://www.metp.net.cn":                          &Result{Flag: Domain, Sub: "www", Root: "metp", Tld: "net.cn"},
		"http://net.cn":                                   &Result{Flag: Malformed},
		"http://google.com?q=cats":                        &Result{Flag: Domain, Sub: "", Root: "google", Tld: "com"},
		"https://mail.google.com/mail":                    &Result{Flag: Domain, Sub: "mail", Root: "google", Tld: "com"},
		"ssh://mail.google.com/mail":                      &Result{Flag: Domain, Sub: "mail", Root: "google", Tld: "com"},
		"//mail.google.com/mail":                          &Result{Flag: Domain, Sub: "mail", Root: "google", Tld: "com"},
		"mail.google.com/mail":                            &Result{Flag: Domain, Sub: "mail", Root: "google", Tld: "com"},
		"9down.cc.html&amp;sa=u&amp;ei=4sfsul-ximsb4ateiicaag&amp;ved=0cbkqfjac&amp;usg=afqjcnfmetjm8-gpgyszv9l1h6_5p369yg/wp-content/themes/airfolio/scripts/timthumb.php": &Result{Flag: Domain, Sub: "", Root: "9down", Tld: "cc"},
		"cy":                  &Result{Flag: Malformed},
		"c.cy":                &Result{Flag: Domain, Sub: "", Root: "c", Tld: "cy"},
		"b.c.cy":              &Result{Flag: Domain, Sub: "b", Root: "c", Tld: "cy"},
		"a.b.c.cy":            &Result{Flag: Domain, Sub: "a.b", Root: "c", Tld: "cy"},
		"b.ide.kyoto.jp":      &Result{Flag: Domain, Sub: "", Root: "b", Tld: "ide.kyoto.jp"},
		"a.b.ide.kyoto.jp":    &Result{Flag: Domain, Sub: "a", Root: "b", Tld: "ide.kyoto.jp"},
		"b.c.kobe.jp":         &Result{Flag: Domain, Sub: "", Root: "b", Tld: "c.kobe.jp"},
		"a.b.c.kobe.jp":       &Result{Flag: Domain, Sub: "a", Root: "b", Tld: "c.kobe.jp"},
		"city.kobe.jp":        &Result{Flag: Domain, Sub: "", Root: "city", Tld: "kobe.jp"},
		"city.a.kobe.jp":      &Result{Flag: Domain, Sub: "", Root: "city", Tld: "a.kobe.jp"},
		"blogspot.co.uk":      &Result{Flag: Malformed},
		"blah.blogspot.co.uk": &Result{Flag: Domain, Sub: "", Root: "blah", Tld: "blogspot.co.uk"},
	}
	for url, expected := range cases {
		returned := tldExtract.Extract(url)
		assert(url, expected, returned, t)
	}
}
