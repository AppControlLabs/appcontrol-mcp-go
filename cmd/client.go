package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows/registry"
)

const (
	defaultPort = 19780
	regPath     = `SOFTWARE\AppControl\Settings`
)

// Client is an HTTP client for the AppControl service MCP API.
type Client struct {
	mu         sync.Mutex
	baseURL    string
	token      string
	httpClient *http.Client
}

var (
	clientMu sync.Mutex
	client   *Client
)

// getClient returns the shared API client, creating it on first use.
// Retries creation if a previous attempt failed.
func getClient() (*Client, error) {
	clientMu.Lock()
	defer clientMu.Unlock()
	if client != nil {
		return client, nil
	}
	c, err := newClient()
	if err != nil {
		return nil, err
	}
	client = c
	return client, nil
}

func readRegistryString(key registry.Key, name string) string {
	val, _, err := key.GetStringValue(name)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(val)
}

func readRegistryDWORD(key registry.Key, name string) uint32 {
	val, _, err := key.GetIntegerValue(name)
	if err != nil {
		return 0
	}
	return uint32(val)
}

func newClient() (*Client, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, regPath, registry.QUERY_VALUE)
	if err != nil {
		return nil, fmt.Errorf(
			"could not open registry key HKLM\\%s. Is the AppControl service running with MCP enabled?",
			regPath,
		)
	}
	defer key.Close()

	token := readRegistryString(key, "McpToken")
	if token == "" {
		return nil, fmt.Errorf(
			"could not read MCP token from registry HKLM\\%s\\McpToken. Is the AppControl service running with MCP enabled?",
			regPath,
		)
	}

	port := int(readRegistryDWORD(key, "McpPort"))
	if port == 0 {
		port = defaultPort
	}

	return &Client{
		baseURL:    fmt.Sprintf("http://127.0.0.1:%d", port),
		token:      token,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// refreshCredentials re-reads token and port from registry. Returns true if anything changed.
func (c *Client) refreshCredentials() bool {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, regPath, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer key.Close()

	changed := false

	newToken := readRegistryString(key, "McpToken")
	if newToken != "" && newToken != c.token {
		c.token = newToken
		changed = true
	}

	port := int(readRegistryDWORD(key, "McpPort"))
	if port == 0 {
		port = defaultPort
	}
	newBase := fmt.Sprintf("http://127.0.0.1:%d", port)
	if newBase != c.baseURL {
		c.baseURL = newBase
		changed = true
	}

	return changed
}

// Get makes an authenticated GET request and returns the raw response body.
// Automatically refreshes credentials and retries on 401.
func (c *Client) Get(path string, params url.Values) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	body, status, err := c.doGet(path, params)
	if err != nil {
		return "", err
	}

	if status == http.StatusUnauthorized && c.refreshCredentials() {
		body, status, err = c.doGet(path, params)
		if err != nil {
			return "", err
		}
	}

	if status == http.StatusUnauthorized {
		return "", fmt.Errorf("authentication failed. The MCP token may be expired")
	}
	if status < 200 || status >= 300 {
		return "", fmt.Errorf("API error %d: %s", status, body)
	}

	return body, nil
}

func (c *Client) doGet(path string, params url.Values) (string, int, error) {
	u := c.baseURL + path
	if len(params) > 0 {
		u += "?" + params.Encode()
	}

	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", resp.StatusCode, err
	}
	return string(b), resp.StatusCode, nil
}

// Parameter helpers for building url.Values

func setStr(params url.Values, key, val string) {
	if val != "" {
		params.Set(key, val)
	}
}

func setInt(params url.Values, key string, val int) {
	if val != 0 {
		params.Set(key, strconv.Itoa(val))
	}
}

func setInt64(params url.Values, key string, val int64) {
	if val != 0 {
		params.Set(key, strconv.FormatInt(val, 10))
	}
}

func setBool(params url.Values, key string, val bool) {
	if val {
		params.Set(key, "1")
	}
}

func setIntSlice(params url.Values, key string, vals []int) {
	if len(vals) == 0 {
		return
	}
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = strconv.Itoa(v)
	}
	params.Set(key, strings.Join(parts, ","))
}
