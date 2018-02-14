package tldextract

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"regexp"
	"strings"
)

//used for Result.Flag
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
	CacheFile  string
	rootNode   *Trie
	debug      bool
	noValidate bool // do not validate URL schema
	noStrip    bool // do not strip .html suffix from URL
}

type Trie struct {
	ExceptRule bool
	ValidTld   bool
	matches    map[string]*Trie
}

var (
	schemaregex = regexp.MustCompile(`^([abcdefghijklmnopqrstuvwxyz0123456789\+\-\.]+:)?//`)
	domainregex = regexp.MustCompile(`^[a-z0-9-]{1,63}$`)
	ip4regex    = regexp.MustCompile(`(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])`)
)

// New creates a new *TLDExtract, it may be shared between goroutines, we usually need a single instance in an application.
func New(cacheFile string, debug bool) (*TLDExtract, error) {
	data, err := ioutil.ReadFile(cacheFile)
	if err != nil {
		data, err = download()
		if err != nil {
			return &TLDExtract{}, err
		}
		if err = ioutil.WriteFile(cacheFile, data, 0644); err != nil {
			return &TLDExtract{}, err
		}
	}
	ts := strings.Split(string(data), "\n")
	newMap := make(map[string]*Trie)
	rootNode := &Trie{ExceptRule: false, ValidTld: false, matches: newMap}
	for _, t := range ts {
		if t != "" && !strings.HasPrefix(t, "//") {
			t = strings.TrimSpace(t)
			exceptionRule := t[0] == '!'
			if exceptionRule {
				t = t[1:]
			}
			addTldRule(rootNode, strings.Split(t, "."), exceptionRule)
		}
	}

	return &TLDExtract{CacheFile: cacheFile, rootNode: rootNode, debug: debug}, nil
}

// SetNoValidate disables schema check in order to increase performance.
func (extract *TLDExtract) SetNoValidate() {
	extract.noValidate = true
}

// SetNoStrip disables URL stripping in order to increase performance.
func (extract *TLDExtract) SetNoStrip() {
	extract.noStrip = true
}

func addTldRule(rootNode *Trie, labels []string, ex bool) {
	numlabs := len(labels)
	t := rootNode
	for i := numlabs - 1; i >= 0; i-- {
		lab := labels[i]
		m, found := t.matches[lab]
		if !found {
			except := ex
			valid := !ex && i == 0
			newMap := make(map[string]*Trie)
			t.matches[lab] = &Trie{ExceptRule: except, ValidTld: valid, matches: newMap}
			m = t.matches[lab]
		}
		t = m
	}
}

func (extract *TLDExtract) Extract(u string) *Result {
	input := u
	u = strings.ToLower(u)
	if !extract.noValidate {
		u = schemaregex.ReplaceAllString(u, "")
		i := strings.Index(u, "@")
		if i != -1 {
			u = u[i+1:]
		}

		index := strings.IndexFunc(u, func(r rune) bool {
			switch r {
			case '&', '/', '?', ':', '#':
				return true
			}
			return false
		})
		if index != -1 {
			u = u[0:index]
		}
	}
	if !extract.noStrip {
		if strings.HasSuffix(u, ".html") {
			u = u[0 : len(u)-len(".html")]
		}
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
				return &Result{Flag: Ip4, Root: url}
			}
			return &Result{Flag: Ip6, Root: url}
		}
		return &Result{Flag: Malformed}
	}
	sub, root := subdomain(domain)
	if domainregex.MatchString(root) {
		return &Result{Flag: Domain, Root: root, Sub: sub, Tld: tld}
	}
	return &Result{Flag: Malformed}
}

func (extract *TLDExtract) extractTld(url string) (domain, tld string) {
	spl := strings.Split(url, ".")
	tldIndex, validTld := extract.getTldIndex(spl)
	if validTld {
		domain = strings.Join(spl[:tldIndex], ".")
		tld = strings.Join(spl[tldIndex:], ".")
	} else {
		domain = url
	}
	return
}

func (extract *TLDExtract) getTldIndex(labels []string) (int, bool) {
	t := extract.rootNode
	parentValid := false
	for i := len(labels) - 1; i >= 0; i-- {
		lab := labels[i]
		n, found := t.matches[lab]
		_, starfound := t.matches["*"]

		switch {
		case found && !n.ExceptRule:
			parentValid = n.ValidTld
			t = n
		// Found an exception rule
		case found:
			fallthrough
		case parentValid:
			return i + 1, true
		case starfound:
			parentValid = true
		default:
			return -1, false
		}
	}
	return -1, false
}

//return sub domain,root domain
func subdomain(d string) (string, string) {
	ps := strings.Split(d, ".")
	l := len(ps)
	if l == 1 {
		return "", d
	}
	return strings.Join(ps[0:l-1], "."), ps[l-1]
}

func download() ([]byte, error) {
	u := "https://publicsuffix.org/list/public_suffix_list.dat"
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
