package goproxy_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/elazarl/goproxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWebSocketHeadersOnNonSwitchingResponse(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Connection", "Upgrade")
		w.Header().Set("Upgrade", "websocket")
		_, _ = io.WriteString(w, "body")
	}))
	defer backend.Close()

	proxyServer := httptest.NewServer(goproxy.NewProxyHttpServer())
	defer proxyServer.Close()
	proxyURL, err := url.Parse(proxyServer.URL)
	require.NoError(t, err)
	conn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", proxyURL.Host)
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))

	request := "GET " + backend.URL + " HTTP/1.1\r\n" +
		"Host: " + backend.Listener.Addr().String() + "\r\n" +
		"Connection: Upgrade\r\n" +
		"Upgrade: websocket\r\n\r\n"
	_, err = io.WriteString(conn, request)
	require.NoError(t, err)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "body", string(body))
}

func TestWebSocketMitm(t *testing.T) {
	// Start a WebSocket echo server
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			InsecureSkipVerify: true,
		})
		if err != nil {
			return
		}
		defer func() {
			_ = c.Close(websocket.StatusNormalClosure, "")
		}()

		ctx := r.Context()
		for {
			mt, message, err := c.Read(ctx)
			if err != nil {
				break
			}
			err = c.Write(ctx, mt, append([]byte("ECHO: "), message...))
			if err != nil {
				break
			}
		}
	}))
	backend.StartTLS()
	defer backend.Close()

	// Start goproxy
	proxy := goproxy.NewProxyHttpServer()
	proxy.Tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)

	proxyServer := httptest.NewServer(proxy)
	defer proxyServer.Close()

	// Configure WebSocket client to use proxy
	proxyURL, err := url.Parse(proxyServer.URL)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	c, _, err := websocket.Dial(ctx, backend.URL, &websocket.DialOptions{
		HTTPClient: &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyURL(proxyURL),
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		},
	})
	require.NoError(t, err)
	defer func() {
		_ = c.Close(websocket.StatusNormalClosure, "")
	}()

	// Verify bidirectional communication
	message := []byte("Hello WebSocket")
	err = c.Write(ctx, websocket.MessageText, message)
	require.NoError(t, err)

	mt, response, err := c.Read(ctx)
	require.NoError(t, err)

	assert.Equal(t, websocket.MessageText, mt)
	assert.Equal(t, "ECHO: Hello WebSocket", string(response))
}
