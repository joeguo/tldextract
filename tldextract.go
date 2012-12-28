package tldextract

import (
	"io/ioutil"
	"net/http"
	"strings"
	"regexp"
	"net"
	"bytes"
	"fmt"
)

const (
	Malformed = iota
	Domain
	Ip4
	Ip6
)

type Result struct {
	Flag int
	Sub  string
	Root string
	Tld  string
}

type TLDExtract struct {
	CacheFile string
	tlds map[string]bool
	debug     bool
}

var (
	schemaregex = regexp.MustCompile("^([abcdefghijklmnopqrstuvwxyz0123456789\\+\\-\\.]+:)?//")
	domainregex = regexp.MustCompile("^[a-z0-9-]{2,63}$")
	ip4regex    = regexp.MustCompile("(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])")
)

func New(cacheFile string, debug bool) *TLDExtract {
	data, err := ioutil.ReadFile(cacheFile)
	if err != nil {
		data, err = download()
		if err != nil {
			panic(err)
		}
		ioutil.WriteFile(cacheFile, data, 0644)
	}
	ts := strings.Split(string(data), "\n")
	tlds := make(map[string]bool, len(ts))
	for _, t := range (ts) {
		if t != "" {
			tlds[t] = true
		}
	}
	return &TLDExtract{CacheFile:cacheFile, tlds:tlds, debug:debug}
}

func (extract *TLDExtract) Extract(u string) *Result {
	input := u
	u = strings.ToLower(u)
	u = schemaregex.ReplaceAllString(u, "")
	i := strings.Index(u, "@")
	if i != -1 {
		u = u[i + 1:]
	}

	index := strings.IndexFunc(u, func(r rune) bool {
			switch r{
			case '&', '/', '?', ':':
				return true
			}
			return false
		})
	if index != -1 {
		u = u[0:index]
	}
//	u = strings.Split(u, "&")[0]
//	u = strings.Split(u, "/")[0]
//	u = strings.Split(u, "?")[0]
//	u = strings.Split(u, ":")[0]

	if strings.HasSuffix(u, ".html") {
		u = u[0:len(u) - len(".html")]
	}
	if extract.debug {
		fmt.Printf("%s;%s\n", u, input)
	}
	return extract.extract(u)
}

func (extract *TLDExtract) extract(url string) *Result {
	domain, tld := extract.extractTld(url)
	if tld == "" {
		ip := net.ParseIP(url)
		if ip != nil {
			if ip4regex.MatchString(url) {
				return &Result{Flag:Ip4, Root:url}
			}
			return &Result{Flag:Ip6, Root:url}
		}
		return &Result{Flag:Malformed}
	}
	sub, root := subdomain(domain)
	if domainregex.MatchString(root) {
		return &Result{Flag:Domain, Root:root, Sub:sub, Tld:tld}
	}
	return &Result{Flag:Malformed}
}

func (extract *TLDExtract) extractTld(url string) (string, string) {
	spl := strings.Split(url, ".")
	for i := range (spl) {
		maybe_tld := strings.Join(spl[i:], ".")
		exception_tld := "!" + maybe_tld
		if _, ok := extract.tlds[exception_tld]; ok {
			return strings.Join(spl[:i + 1], "."), strings.Join(spl[i + 1:], ".")
		}
		if len(spl) > i + 1 {
			wildcard_tld := "*." + strings.Join(spl[i + 1:], ".")
			if _, ok := extract.tlds[wildcard_tld]; ok {
				return strings.Join(spl[:i], "."), maybe_tld
			}
		}
		if _, ok := extract.tlds[maybe_tld]; ok {
			return strings.Join(spl[:i], "."), maybe_tld
		}
	}
	return url, ""
}

//return sub domain,root domain
func subdomain(d string) (string , string) {
	ps := strings.Split(d, ".")
	l := len(ps)
	if l == 1 {
		return "", d
	}
	return strings.Join(ps[0:l - 1], "."), ps[l - 1]
}

func download() ([]byte, error) {
	u := "http://mxr.mozilla.org/mozilla-central/source/netwerk/dns/effective_tld_names.dat?raw=1"
	resp, err := http.Get(u)
	if err != nil {
		return []byte(""), err
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)

	lines := strings.Split(string(body), "\n")
	var buffer bytes.Buffer

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "//") {
			buffer.WriteString(line)
			buffer.WriteString("\n")

		}
	}

	return buffer.Bytes(), nil
}
