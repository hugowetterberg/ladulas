package bridge

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Call runs one request through the bridge handler and collects the response.
//
// This is the answer to open question 5. A webview cannot be given a socket; it
// can be given a way to intercept the loads it makes — WKURLSchemeHandler on
// iOS, WebViewClient.shouldInterceptRequest on Android — and what an intercept
// hands over is a method, a path and a body. So that is the whole contract, and
// the desktop's Wails asset handler, iOS and Android are three deliveries of it
// rather than three APIs.
//
// The desktop does not use this: Wails serves the http.Handler directly, which
// is the same thing with the plumbing already written. gomobile bindings for
// mobile hosts wrap Call, since neither []byte-in-[]byte-out nor a Go
// http.Handler crosses that boundary on its own.
func Call(handler http.Handler, req *CallRequest) *CallResponse {
	target := req.Path
	if !strings.HasPrefix(target, "/") {
		target = "/" + target
	}

	parsed, err := url.ParseRequestURI(target)
	if err != nil {
		return &CallResponse{
			Status:      http.StatusBadRequest,
			ContentType: "application/json; charset=utf-8",
			Body:        []byte(fmt.Sprintf(`{"error":%q}`, "bad path")),
		}
	}

	method := req.Method
	if method == "" {
		method = http.MethodGet
	}

	httpReq, err := http.NewRequestWithContext(
		req.context(), method, parsed.String(), bytes.NewReader(req.Body))
	if err != nil {
		return &CallResponse{
			Status:      http.StatusBadRequest,
			ContentType: "application/json; charset=utf-8",
			Body:        []byte(fmt.Sprintf(`{"error":%q}`, err.Error())),
		}
	}

	if req.ContentType != "" {
		httpReq.Header.Set("Content-Type", req.ContentType)
	}

	recorder := &recorder{header: http.Header{}}

	handler.ServeHTTP(recorder, httpReq)

	return &CallResponse{
		Status:      recorder.status(),
		ContentType: recorder.header.Get("Content-Type"),
		Header:      recorder.header,
		Body:        recorder.body.Bytes(),
	}
}

// CallRequest is what a host's URL interception saw.
type CallRequest struct {
	Method      string
	Path        string
	ContentType string
	Body        []byte
	Ctx         context.Context //nolint:containedctx // this is a request record
}

func (c *CallRequest) context() context.Context {
	if c.Ctx == nil {
		return context.Background()
	}

	return c.Ctx
}

// CallResponse is what it should hand back to the webview.
type CallResponse struct {
	Status      int
	ContentType string
	Header      http.Header
	Body        []byte
}

// recorder is a minimal http.ResponseWriter. net/http/httptest has one, but it
// is a testing package and this runs in the shipped mobile builds.
type recorder struct {
	header      http.Header
	body        bytes.Buffer
	wroteStatus int
}

var _ http.ResponseWriter = (*recorder)(nil)

func (r *recorder) Header() http.Header {
	return r.header
}

func (r *recorder) Write(p []byte) (int, error) {
	if r.wroteStatus == 0 {
		r.wroteStatus = http.StatusOK
	}

	n, err := r.body.Write(p)
	if err != nil {
		return n, fmt.Errorf("buffer the response: %w", err)
	}

	return n, nil
}

func (r *recorder) WriteHeader(status int) {
	if r.wroteStatus == 0 {
		r.wroteStatus = status
	}
}

func (r *recorder) status() int {
	if r.wroteStatus == 0 {
		return http.StatusOK
	}

	return r.wroteStatus
}

// ReadAll is what a host with an io.Reader body — an Android WebResourceRequest
// wrapper, say — uses to fill in CallRequest.Body.
func ReadAll(body io.Reader) ([]byte, error) {
	if body == nil {
		return nil, nil
	}

	out, err := io.ReadAll(body)
	if err != nil {
		return nil, fmt.Errorf("read the request body: %w", err)
	}

	return out, nil
}
