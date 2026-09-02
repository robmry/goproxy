package goproxy

import (
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
)

var errInvalidProtocolSwitch = errors.New("backend returned an invalid protocol switch")

func headerContains(header http.Header, name string, value string) bool {
	for _, token := range headerTokens(header, name) {
		if strings.EqualFold(value, token) {
			return true
		}
	}
	return false
}

func headerTokens(header http.Header, name string) []string {
	var tokens []string
	for _, value := range header.Values(name) {
		for _, token := range strings.Split(value, ",") {
			if token = strings.TrimSpace(token); token != "" {
				tokens = append(tokens, token)
			}
		}
	}
	return tokens
}

func sanitizeUpgradeConnection(header http.Header) {
	var kept []string
	keepHTTP2Settings := false
	offersH2C := headerContains(header, "Upgrade", "h2c")
	for _, token := range headerTokens(header, "Connection") {
		switch {
		case strings.EqualFold(token, "Upgrade"):
			kept = append(kept, token)
		case strings.EqualFold(token, "HTTP2-Settings") && offersH2C:
			kept = append(kept, token)
			keepHTTP2Settings = true
		default:
			header.Del(token)
		}
	}
	if !keepHTTP2Settings {
		header.Del("HTTP2-Settings")
	}
	header.Set("Connection", strings.Join(kept, ", "))
}

func isWebSocketHandshake(header http.Header) bool {
	return headerContains(header, "Connection", "Upgrade") &&
		headerContains(header, "Upgrade", "websocket")
}

func isUpgradeHandshake(header http.Header) bool {
	return headerContains(header, "Connection", "Upgrade") && header.Get("Upgrade") != ""
}

// MatchingUpgrade accepts a 101 response only when it selects protocols the
// client offered and both messages nominate a protocol switch.
func MatchingUpgrade(ctx *ProxyCtx, resp *http.Response) bool {
	if ctx == nil || ctx.Req == nil || resp == nil || resp.StatusCode != http.StatusSwitchingProtocols ||
		!isUpgradeHandshake(ctx.Req.Header) || !isUpgradeHandshake(resp.Header) {
		return false
	}
	selected := headerTokens(resp.Header, "Upgrade")
	if len(selected) == 0 {
		return false
	}
	for _, protocol := range selected {
		if !headerContains(ctx.Req.Header, "Upgrade", protocol) {
			return false
		}
	}
	return true
}

func (proxy *ProxyHttpServer) shouldProxyUpgrade(ctx *ProxyCtx, req *http.Request, resp *http.Response) bool {
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return false
	}
	if proxy.AllowUpgrade != nil {
		ctx.Req = req
		return proxy.AllowUpgrade(ctx, resp)
	}
	return isWebSocketHandshake(resp.Header)
}

func (proxy *ProxyHttpServer) hijackConnection(ctx *ProxyCtx, w http.ResponseWriter) (net.Conn, error) {
	// Connect to Client
	hj, ok := w.(http.Hijacker)
	if !ok {
		panic("httpserver does not support hijacking")
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		ctx.Warnf("Hijack error: %v", err)
		return nil, err
	}
	return clientConn, nil
}

func (proxy *ProxyHttpServer) proxyUpgrade(ctx *ProxyCtx, remoteConn io.ReadWriter, proxyClient io.ReadWriter) {
	// 2 is the number of goroutines, this code is implemented according to
	// https://stackoverflow.com/questions/52031332/wait-for-one-goroutine-to-finish
	waitChan := make(chan struct{}, 2)
	go func() {
		_ = copyOrWarn(ctx, remoteConn, proxyClient)
		waitChan <- struct{}{}
	}()

	go func() {
		_ = copyOrWarn(ctx, proxyClient, remoteConn)
		waitChan <- struct{}{}
	}()

	// Closing both sides after either copy ends unblocks the other copy so the
	// relay can return.
	<-waitChan
	if closer, ok := remoteConn.(io.Closer); ok {
		_ = closer.Close()
	}
	if closer, ok := proxyClient.(io.Closer); ok {
		_ = closer.Close()
	}
	<-waitChan
}
