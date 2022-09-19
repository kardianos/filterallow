package main

import (
	"net/url"
	"testing"
)

func TestMatch(t *testing.T) {
	parse := func(s string) *url.URL {
		U, err := url.Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		return U
	}
	list := []struct {
		Name  string
		U     *url.URL
		Rule  []Rule
		Match bool
	}{
		{
			Name:  "HostMatch",
			U:     parse("https://youtube.com/v=abc123"),
			Rule:  []Rule{{Host: "youtube.com"}},
			Match: true,
		},
		{
			Name:  "HostNoMatch",
			U:     parse("https://notsite.com/v=abc123"),
			Rule:  []Rule{{Host: "youtube.com"}},
			Match: false,
		},
	}

	for _, item := range list {
		t.Run(item.Name, func(t *testing.T) {
			got := match(item.U, item.Rule)
			want := item.Match

			if got != want {
				t.Fatalf("got %t, want %t", got, want)
			}
		})
	}
}
