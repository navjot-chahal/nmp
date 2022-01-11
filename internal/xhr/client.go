package xhr

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/navjot-chahal/nmp/internal/errors"
)

type Client struct {
	headers http.Header
	http    *http.Client
}

// Creates a new instance of Client
func New(headers *http.Header) *Client {
	c := &Client{
		http: &http.Client{Timeout: 20 * time.Second},
	}
	if headers != nil {
		c.headers = headers.Clone()
	}
	return c
}

func (c *Client) Get(url string, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, url, bytes.NewReader([]byte{}))
	if err != nil {
		return nil, err
	}
	c.injectHeaders(req, headers)
	return c.http.Do(req)
}

func (c *Client) Post(url string, data io.Reader, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, url, data)
	if err != nil {
		return nil, err
	}
	c.injectHeaders(req, headers)
	return c.http.Do(req)
}

func (c *Client) Put(url string, data io.Reader, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPut, url, data)
	if err != nil {
		return nil, err
	}
	c.injectHeaders(req, headers)
	return c.http.Do(req)
}

func (c *Client) Delete(url string, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodDelete, url, bytes.NewReader([]byte{}))
	if err != nil {
		return nil, err
	}
	c.injectHeaders(req, headers)
	return c.http.Do(req)
}

func (c *Client) injectHeaders(req *http.Request, headers map[string]string) {
	if c.headers != nil && len(c.headers) > 0 {
		req.Header = c.headers.Clone()
	}
	req.Header.Set("Content-Type", "application/json")
	for name, value := range headers {
		req.Header.Add(name, value)
	}
}

// DecodeResponse decodes and parses response body
func (c *Client) DecodeResponse(res *http.Response, v interface{}) error {
	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusBadRequest {
		return errors.LoginidErrorFromReader(res.Body)
	}

	if res.StatusCode != http.StatusNoContent && res.StatusCode != http.StatusAccepted {
		if err := json.NewDecoder(res.Body).Decode(v); err != nil {
			return err
		}
		return res.Body.Close()
	}
	return nil
}
