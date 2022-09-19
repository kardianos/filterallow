package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/kardianos/mitmproxy/cert"
	"github.com/kardianos/mitmproxy/proxy"
	"github.com/kardianos/task"
	"go4.org/strutil"
)

func main() {
	err := task.Start(context.Background(), time.Second*2, runMITM)
	if err != nil {
		log.Fatal(err)
	}
}

func defenv(name string, def string) string {
	v := os.Getenv(name)
	if len(v) > 0 {
		return v
	}
	return def
}

type RuleQuery struct {
	K string
	V string
}

type Rule struct {
	Host  string
	Path  string
	Query RuleQuery
}

type Config struct {
	DefaultReject bool
	Reject        []Rule
	Accept        []Rule
}

func runMITM(ctx context.Context) error {
	addr := flag.String("addr", defenv("ADDR", ":9080"), "proxy listen address")
	certpath := flag.String("certpath", defenv("CERTPATH", ""), "certificate CA path")
	configpath := flag.String("configpath", defenv("CONFIGPATH", ""), "configuration file")
	flag.Parse()

	var c Config
	if len(*configpath) > 0 {
		x, err := os.ReadFile(*configpath)
		if err != nil {
			return err
		}
		err = json.Unmarshal(x, &c)
		if err != nil {
			return err
		}
	}

	load, err := cert.NewPathLoader(*certpath)
	if err != nil {
		return err
	}
	log.Println("cert path:", load.StorePath)
	ca, err := cert.New(load)
	if err != nil {
		return err
	}

	p, err := proxy.NewProxy(&proxy.Options{
		Addr: *addr,
		CA:   ca,
	})
	if err != nil {
		return err
	}

	h := &handler{
		Config: c,
	}

	p.AddAddon(h)

	log.Println("Starting...")

	go func() {
		<-ctx.Done()
		log.Println("Stopping...")
		xctx, cancel := context.WithTimeout(context.Background(), time.Second*1)
		defer cancel()

		p.Shutdown(xctx)
	}()

	return p.Start()
}

func loadCert(p string) (tls.Certificate, error) {
	x, err := os.ReadFile(p)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(x, x)
}

type handler struct {
	proxy.BaseAddon

	Config Config
}

func match(U *url.URL, list []Rule) bool {
	zrq := RuleQuery{}
	var v url.Values
	var parsed bool
	for _, rule := range list {
		if len(rule.Host) > 0 && !strutil.ContainsFold(U.Host, rule.Host) {
			continue
		}
		if len(rule.Path) > 0 && !strutil.ContainsFold(U.Path, rule.Path) {
			continue
		}

		if rule.Query != zrq {
			if !parsed {
				v = U.Query()
				parsed = true
			}
			q := rule.Query
			vv, ok := v[q.K]
			if !ok {
				continue
			}
			if len(q.V) > 0 { // If value is blank, match if present.
				match := false
				for _, v := range vv {
					if strutil.ContainsFold(v, q.V) {
						match = true
						break
					}
				}
				if !match {
					continue
				}
			}
		}
		return true
	}
	return false
}

// HTTP request headers were successfully read. At this point, the body is empty.
func (h *handler) Requestheaders(f *proxy.Flow) {
	U := f.Request.URL

	// If default reject.
	// Then accept.
	// Lastly reject.
	//
	// If default accept.
	// Then reject.
	// Lastly accept.
	c := h.Config
	reject := c.DefaultReject
	if c.DefaultReject {
		if match(U, c.Accept) {
			reject = false
		}
		if !reject && match(U, c.Reject) {
			reject = true
		}
	} else {
		if match(U, c.Reject) {
			reject = true
		}
		if reject && match(U, c.Accept) {
			reject = false
		}
	}
	if reject {
		log.Println("reject", U.Host, U.Path, U.RawQuery)
		f.Response = &proxy.Response{
			StatusCode: http.StatusNotAcceptable,
			Body:       []byte(`Not Allowed`),
		}
		return
	}

	log.Println("allow", U.Host, U.Path, U.RawQuery)
}
