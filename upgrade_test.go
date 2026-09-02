package goproxy_test

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func TestGenericUpgradeOptIn(t *testing.T) {
	for _, mitm := range []bool{false, true} {
		t.Run(fmt.Sprintf("mitm=%t", mitm), func(t *testing.T) {
			backend := newUpgradeServer(t, "tcp", mitm)
			proxy := goproxy.NewProxyHttpServer()
			proxy.Tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
			proxy.AllowUpgrade = goproxy.MatchingUpgrade
			if mitm {
				proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
			}
			proxyServer := httptest.NewServer(proxy)
			t.Cleanup(proxyServer.Close)

			conn := dialProxy(t, proxyServer.URL)
			if mitm {
				connect(t, conn, backend.Listener.Addr().String())
				tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
				require.NoError(t, tlsConn.HandshakeContext(t.Context()))
				conn = tlsConn
			}
			t.Cleanup(func() { _ = conn.Close() })
			require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))

			target := backend.URL + "/sanitize"
			if mitm {
				target = "/sanitize"
			}
			_, err := fmt.Fprintf(conn, "GET %s HTTP/1.1\r\n"+
				"Host: %s\r\n"+
				"Connection: X-Injected, Upgrade, HTTP2-Settings\r\n"+
				"Upgrade: websocket\r\n"+
				"Upgrade: tcp\r\n"+
				"HTTP2-Settings: remove-me\r\n"+
				"X-Injected: remove-me\r\n\r\n", target, backend.Listener.Addr().String())
			require.NoError(t, err)
			reader := bufio.NewReader(conn)
			resp, err := http.ReadResponse(reader, nil)
			require.NoError(t, err)
			require.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)
			require.Equal(t, "tcp", resp.Header.Get("Upgrade"))

			_, err = conn.Write([]byte("ping"))
			require.NoError(t, err)
			echo := make([]byte, 4)
			_, err = io.ReadFull(reader, echo)
			require.NoError(t, err)
			require.Equal(t, "ping", string(echo))
		})
	}
}

func TestMatchingUpgrade(t *testing.T) {
	request := func(connection, upgrade string) *http.Request {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com/", http.NoBody)
		req.Header.Set("Connection", connection)
		req.Header.Set("Upgrade", upgrade)
		return req
	}
	response := func(status int, connection, upgrade string) *http.Response {
		return &http.Response{StatusCode: status, Header: http.Header{
			"Connection": {connection},
			"Upgrade":    {upgrade},
		}}
	}

	for name, tc := range map[string]struct {
		ctx  *goproxy.ProxyCtx
		resp *http.Response
		want bool
	}{
		"matching protocol": {
			ctx:  &goproxy.ProxyCtx{Req: request("keep-alive, Upgrade", "websocket, tcp")},
			resp: response(http.StatusSwitchingProtocols, "Upgrade", "tcp"),
			want: true,
		},
		"missing context": {
			resp: response(http.StatusSwitchingProtocols, "Upgrade", "tcp"),
		},
		"missing request": {
			ctx:  &goproxy.ProxyCtx{},
			resp: response(http.StatusSwitchingProtocols, "Upgrade", "tcp"),
		},
		"missing response": {
			ctx: &goproxy.ProxyCtx{Req: request("Upgrade", "tcp")},
		},
		"non-switching response": {
			ctx:  &goproxy.ProxyCtx{Req: request("Upgrade", "tcp")},
			resp: response(http.StatusOK, "Upgrade", "tcp"),
		},
		"request does not nominate switch": {
			ctx:  &goproxy.ProxyCtx{Req: request("keep-alive", "tcp")},
			resp: response(http.StatusSwitchingProtocols, "Upgrade", "tcp"),
		},
		"response does not nominate switch": {
			ctx:  &goproxy.ProxyCtx{Req: request("Upgrade", "tcp")},
			resp: response(http.StatusSwitchingProtocols, "keep-alive", "tcp"),
		},
		"response selects unoffered protocol": {
			ctx:  &goproxy.ProxyCtx{Req: request("Upgrade", "websocket")},
			resp: response(http.StatusSwitchingProtocols, "Upgrade", "tcp"),
		},
	} {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, tc.want, goproxy.MatchingUpgrade(tc.ctx, tc.resp))
		})
	}
}

func TestH2CUpgradePreservesHTTP2SettingsConnectionToken(t *testing.T) {
	backend := httptest.NewServer(h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), &http2.Server{}))
	t.Cleanup(backend.Close)

	proxy := goproxy.NewProxyHttpServer()
	proxy.AllowUpgrade = goproxy.MatchingUpgrade
	proxyServer := httptest.NewServer(proxy)
	t.Cleanup(proxyServer.Close)
	conn := dialProxy(t, proxyServer.URL)
	t.Cleanup(func() { _ = conn.Close() })
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))

	_, err := fmt.Fprintf(conn, "GET %s/upgrade HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Connection: X-Injected, Upgrade, HTTP2-Settings\r\n"+
		"Upgrade: h2c\r\n"+
		"HTTP2-Settings: AAMAAABkAAQAAP__\r\n"+
		"X-Injected: remove-me\r\n\r\n", backend.URL, backend.Listener.Addr().String())
	require.NoError(t, err)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)
	require.Equal(t, "h2c", resp.Header.Get("Upgrade"))
	require.NoError(t, resp.Body.Close())
}

func TestGenericUpgradeRequiresOptIn(t *testing.T) {
	backend := newUpgradeServer(t, "tcp", false)
	proxyServer := httptest.NewServer(goproxy.NewProxyHttpServer())
	t.Cleanup(proxyServer.Close)
	conn := dialProxy(t, proxyServer.URL)
	t.Cleanup(func() { _ = conn.Close() })
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))

	_, err := fmt.Fprintf(conn, "GET %s/upgrade HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Connection: Upgrade\r\n"+
		"Upgrade: tcp\r\n\r\n", backend.URL, backend.Listener.Addr().String())
	require.NoError(t, err)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadGateway, resp.StatusCode)
}

func TestWebSocketResponseKeepsLegacyBehavior(t *testing.T) {
	backend := newUpgradeServer(t, "websocket", false)
	proxyServer := httptest.NewServer(goproxy.NewProxyHttpServer())
	t.Cleanup(proxyServer.Close)
	conn := dialProxy(t, proxyServer.URL)
	t.Cleanup(func() { _ = conn.Close() })
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))

	_, err := fmt.Fprintf(conn, "GET %s/upgrade HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Upgrade: websocket\r\n\r\n", backend.URL, backend.Listener.Addr().String())
	require.NoError(t, err)
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)

	_, err = conn.Write([]byte("ping"))
	require.NoError(t, err)
	echo := make([]byte, 4)
	_, err = io.ReadFull(reader, echo)
	require.NoError(t, err)
	require.Equal(t, "ping", string(echo))
}

func newUpgradeServer(t *testing.T, protocol string, useTLS bool) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") == "" {
			t.Errorf("upgrade header was not forwarded")
		}
		if r.URL.Path == "/sanitize" {
			if got := r.Header.Get("Connection"); !strings.EqualFold(got, "Upgrade") {
				t.Errorf("connection header = %q, want Upgrade", got)
			}
			if got := r.Header.Get("X-Injected"); got != "" {
				t.Errorf("X-Injected header = %q, want empty", got)
			}
			if got := r.Header.Get("HTTP2-Settings"); got != "" {
				t.Errorf("HTTP2-Settings header = %q, want empty", got)
			}
		}
		conn, rw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		defer conn.Close()
		_, err = fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: %s\r\n\r\n", protocol)
		if err != nil {
			t.Errorf("write response: %v", err)
			return
		}
		if err := rw.Flush(); err != nil {
			t.Errorf("flush response: %v", err)
			return
		}
		if _, err := io.Copy(conn, rw); err != nil {
			t.Errorf("echo upgraded connection: %v", err)
		}
	}))
	if useTLS {
		server.StartTLS()
	} else {
		server.Start()
	}
	t.Cleanup(server.Close)
	return server
}

func dialProxy(t *testing.T, proxyURL string) net.Conn {
	t.Helper()
	u, err := url.Parse(proxyURL)
	require.NoError(t, err)
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(t.Context(), "tcp", u.Host)
	require.NoError(t, err)
	return conn
}

func connect(t *testing.T, conn net.Conn, target string) {
	t.Helper()
	_, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	require.NoError(t, err)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
}
