package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log"
	"net/http"
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

func runMITM(ctx context.Context) error {
	addr := flag.String("addr", ":9080", "proxy listen address")
	flag.Parse()

	load, err := cert.NewPathLoader("")
	if err != nil {
		return err
	}
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

	h := &handler{}

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
}

// HTTP request headers were successfully read. At this point, the body is empty.
func (h *handler) Requestheaders(f *proxy.Flow) {
	U := f.Request.URL

	reject := strutil.ContainsFold(U.RawQuery, "mGxgm-Xo1GE")
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
