package client

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const defaultTimeout = 2 * time.Minute

type HTTPClient struct {
	baseURL    string
	httpClient *http.Client
	token      string
}

type SubfinderRequest struct {
	Tool      string `json:"tool"`
	Domain    string `json:"domain"`
	RawOutput bool   `json:"raw_output,omitempty"`
}

type SubdomainScanResult struct {
	ScanID       string   `json:"scan_id"`
	Subdomain    string   `json:"subdomain"`
	IsAlive      bool     `json:"is_alive"`
	StatusCode   int      `json:"status_code"`
	Title        string   `json:"title"`
	IP           string   `json:"ip"`
	Technologies []string `json:"technologies"`
}

type SubfinderResponse struct {
	ScanID  string                `json:"scan_id"`
	Results []SubdomainScanResult `json:"results"`
}

func NewHTTPClient(baseURL string, token string, timeout time.Duration) *HTTPClient {
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &HTTPClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   strings.TrimSpace(token),
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

func (c *HTTPClient) RunSubfinder(ctx context.Context, req SubfinderRequest) (*SubfinderResponse, error) {
	targetDomain := strings.TrimSpace(req.Domain)
	if targetDomain == "" {
		return nil, fmt.Errorf("domain cannot be empty")
	}

	req.Domain = targetDomain
	if strings.TrimSpace(req.Tool) == "" {
		req.Tool = "subfinder"
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	endpoint := c.baseURL + "/scan-subdomains/" + url.PathEscape(targetDomain)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	c.addAuthHeaders(httpReq)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusBadRequest {
		return nil, c.decodeHTTPError(resp)
	}

	var payload SubfinderResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &payload, nil
}

func (c *HTTPClient) StreamSubfinder(ctx context.Context, req SubfinderRequest, onLine func(string)) (string, error) {
	targetDomain := strings.TrimSpace(req.Domain)
	if targetDomain == "" {
		return "", fmt.Errorf("domain cannot be empty")
	}

	req.Domain = targetDomain
	req.RawOutput = true
	if strings.TrimSpace(req.Tool) == "" {
		req.Tool = "subfinder"
	}

	body, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}

	endpoint := c.baseURL + "/scan-subdomains/stream/" + url.PathEscape(targetDomain)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	c.addAuthHeaders(httpReq)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "text/plain")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusBadRequest {
		return "", c.decodeHTTPError(resp)
	}

	scanID := strings.TrimSpace(resp.Header.Get("X-Scan-ID"))
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		if onLine != nil {
			onLine(scanner.Text())
		}
	}
	if err := scanner.Err(); err != nil {
		return scanID, fmt.Errorf("read stream output: %w", err)
	}

	return scanID, nil
}

func (c *HTTPClient) CancelSubfinder(ctx context.Context, scanID string) error {
	scanID = strings.TrimSpace(scanID)
	if scanID == "" {
		return fmt.Errorf("scan id cannot be empty")
	}

	endpoint := c.baseURL + "/scan-subdomains/" + url.PathEscape(scanID) + "/cancel"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return fmt.Errorf("create cancel request: %w", err)
	}
	c.addAuthHeaders(req)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send cancel request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusBadRequest {
		return c.decodeHTTPError(resp)
	}
	return nil
}

func (c *HTTPClient) addAuthHeaders(req *http.Request) {
	if c.token == "" {
		return
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
}

func (c *HTTPClient) decodeHTTPError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if len(body) == 0 {
		return fmt.Errorf("request failed with status %d", resp.StatusCode)
	}

	var payload struct {
		Detail any `json:"detail"`
	}
	if err := json.Unmarshal(body, &payload); err == nil && payload.Detail != nil {
		switch detail := payload.Detail.(type) {
		case string:
			return fmt.Errorf("request failed (%d): %s", resp.StatusCode, detail)
		default:
			raw, _ := json.Marshal(detail)
			return fmt.Errorf("request failed (%d): %s", resp.StatusCode, string(raw))
		}
	}

	return fmt.Errorf("request failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
}
