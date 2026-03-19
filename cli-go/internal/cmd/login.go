package cmd

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

func newLoginCmd(opts *rootOptions) *cobra.Command {
	var (
		clientID   string
		issuer     string
		noBrowser  bool
		printLink  bool
		redirect   string
		scope      string
		waitWindow time.Duration
	)

	cmd := &cobra.Command{
		Use:   "login",
		Short: "Login via Keycloak and cache your token for CLI commands",
		RunE: func(cmd *cobra.Command, args []string) error {
			clientID = strings.TrimSpace(clientID)
			issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")
			redirect = strings.TrimSpace(redirect)
			scope = strings.TrimSpace(scope)

			if issuer == "" {
				return fmt.Errorf("missing issuer: pass --issuer or set AOF_KEYCLOAK_ISSUER")
			}
			if clientID == "" {
				return fmt.Errorf("missing client id: pass --client-id or set AOF_KEYCLOAK_CLIENT_ID")
			}
			if redirect == "" {
				return fmt.Errorf("missing redirect url")
			}

			redirectURL, err := url.Parse(redirect)
			if err != nil || redirectURL.Scheme == "" || redirectURL.Host == "" {
				return fmt.Errorf("invalid redirect url %q", redirect)
			}
			if !strings.Contains(redirectURL.Host, ":") {
				return fmt.Errorf("redirect url must include host and port, got %q", redirectURL.Host)
			}

			state, err := randomURLSafe(24)
			if err != nil {
				return fmt.Errorf("generate oauth state: %w", err)
			}
			codeVerifier, err := randomURLSafe(64)
			if err != nil {
				return fmt.Errorf("generate pkce verifier: %w", err)
			}
			codeChallenge := pkceS256(codeVerifier)

			authURL := buildAuthURL(issuer, clientID, redirect, scope, state, codeChallenge)
			if printLink {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Login URL:\n%s\n", authURL)
				return nil
			}

			code, err := waitForAuthCode(cmd.Context(), redirectURL, authURL, state, noBrowser, waitWindow, cmd.OutOrStdout())
			if err != nil {
				return err
			}

			tokenResp, err := exchangeAuthCode(cmd.Context(), issuer, clientID, redirect, code, codeVerifier, opts.timeout)
			if err != nil {
				return err
			}
			if strings.TrimSpace(tokenResp.AccessToken) == "" {
				return fmt.Errorf("token endpoint returned an empty access_token")
			}

			record := &storedToken{
				AccessToken: tokenResp.AccessToken,
				ClientID:    clientID,
				Issuer:      issuer,
				TokenType:   tokenResp.TokenType,
			}
			if tokenResp.ExpiresIn > 0 {
				record.ExpiresAt = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
			}
			if err := writeStoredToken(opts.tokenFile, record); err != nil {
				return err
			}

			opts.token = tokenResp.AccessToken
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Login success. Token saved to %s\n", opts.tokenFile)
			if !record.ExpiresAt.IsZero() {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Token expires at %s\n", record.ExpiresAt.Format(time.RFC3339))
			}
			return nil
		},
	}

	cmd.Flags().StringVar(
		&issuer,
		"issuer",
		envOrDefault("AOF_KEYCLOAK_ISSUER", envOrDefault("KEYCLOAK_ISSUER", "http://localhost:8080/auth/realms/myrealm")),
		"Keycloak realm issuer URL",
	)
	cmd.Flags().StringVar(
		&clientID,
		"client-id",
		envOrDefault("AOF_KEYCLOAK_CLIENT_ID", envOrDefault("KEYCLOAK_AUDIENCE", "myclient")),
		"OIDC client_id configured in Keycloak",
	)
	cmd.Flags().StringVar(
		&redirect,
		"redirect-url",
		envOrDefault("AOF_REDIRECT_URL", "http://127.0.0.1:8250/callback"),
		"OIDC redirect URL registered for the client",
	)
	cmd.Flags().StringVar(
		&scope,
		"scope",
		"openid profile email",
		"OIDC scopes to request",
	)
	cmd.Flags().BoolVar(
		&noBrowser,
		"no-browser",
		false,
		"Do not auto-open a browser, only print login URL",
	)
	cmd.Flags().BoolVar(
		&printLink,
		"print-link",
		false,
		"Print login URL and exit without starting callback listener",
	)
	cmd.Flags().DurationVar(
		&waitWindow,
		"wait",
		5*time.Minute,
		"Maximum time to wait for browser login callback",
	)

	return cmd
}

func buildAuthURL(issuer string, clientID string, redirect string, scope string, state string, challenge string) string {
	values := url.Values{}
	values.Set("client_id", clientID)
	values.Set("response_type", "code")
	values.Set("redirect_uri", redirect)
	values.Set("scope", scope)
	values.Set("state", state)
	values.Set("code_challenge", challenge)
	values.Set("code_challenge_method", "S256")
	return issuer + "/protocol/openid-connect/auth?" + values.Encode()
}

func waitForAuthCode(
	parent context.Context,
	redirectURL *url.URL,
	authURL string,
	expectedState string,
	noBrowser bool,
	waitWindow time.Duration,
	out io.Writer,
) (string, error) {
	callbackPath := redirectURL.EscapedPath()
	if callbackPath == "" {
		callbackPath = "/"
	}

	codeCh := make(chan string, 1)
	serverErrCh := make(chan error, 1)
	mux := http.NewServeMux()
	mux.HandleFunc(callbackPath, func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		if query.Get("state") != expectedState {
			http.Error(w, "state mismatch", http.StatusBadRequest)
			return
		}
		if rawErr := query.Get("error"); rawErr != "" {
			http.Error(w, "login denied: "+rawErr, http.StatusBadRequest)
			return
		}
		code := strings.TrimSpace(query.Get("code"))
		if code == "" {
			http.Error(w, "missing authorization code", http.StatusBadRequest)
			return
		}

		_, _ = io.WriteString(w, "Login complete. You can close this tab and return to the terminal.")
		select {
		case codeCh <- code:
		default:
		}
	})

	server := &http.Server{
		Addr:    redirectURL.Host,
		Handler: mux,
	}
	go func() {
		err := server.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			serverErrCh <- err
		}
	}()

	_, _ = fmt.Fprintf(out, "Login URL:\n%s\n", authURL)
	if !noBrowser {
		if err := openBrowser(authURL); err != nil {
			_, _ = fmt.Fprintf(out, "Could not open browser automatically: %v\n", err)
			_, _ = fmt.Fprintln(out, "Please open the URL manually.")
		}
	}

	ctx, cancel := context.WithTimeout(parent, waitWindow)
	defer cancel()
	var code string

	select {
	case code = <-codeCh:
	case err := <-serverErrCh:
		_ = server.Close()
		return "", fmt.Errorf("callback server failed: %w", err)
	case <-ctx.Done():
		_ = server.Close()
		return "", fmt.Errorf("login timed out or canceled")
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer shutdownCancel()
	_ = server.Shutdown(shutdownCtx)

	return code, nil
}

type tokenExchangeResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

func exchangeAuthCode(
	ctx context.Context,
	issuer string,
	clientID string,
	redirect string,
	code string,
	codeVerifier string,
	timeout time.Duration,
) (*tokenExchangeResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", clientID)
	form.Set("code", code)
	form.Set("redirect_uri", redirect)
	form.Set("code_verifier", codeVerifier)

	endpoint := issuer + "/protocol/openid-connect/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	httpClient := &http.Client{Timeout: timeout}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("exchange auth code: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusBadRequest {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return nil, fmt.Errorf("token endpoint failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var payload tokenExchangeResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}
	return &payload, nil
}

func randomURLSafe(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func pkceS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func openBrowser(link string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", link)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", link)
	default:
		cmd = exec.Command("xdg-open", link)
	}
	return cmd.Start()
}
