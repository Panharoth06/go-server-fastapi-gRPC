package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"cli-go/internal/client"

	"github.com/spf13/cobra"
)

var streamResultPattern = regexp.MustCompile(`^\[(UP|DOWN)\]\s+(\S+)\s+code=(\d+)\s+ip=(\S+)\s+title=("(?:[^"\\]|\\.)*")\s+tech=(.*)$`)

func newSubfinderCmd(opts *rootOptions) *cobra.Command {
	var (
		domain string
		json   bool
	)

	cmd := &cobra.Command{
		Use:   "subfinder -d <domain>",
		Short: "Run subfinder via FastAPI without installing local tools",
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(opts.token) == "" {
				return fmt.Errorf("missing auth token: run `aof login` or pass --token")
			}

			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			httpClient := client.NewHTTPClient(opts.apiURL, opts.token, opts.timeout)
			request := client.SubfinderRequest{
				Tool:   "subfinder",
				Domain: domain,
			}

			if json {
				resp, err := httpClient.RunSubfinder(ctx, request)
				if err != nil {
					return err
				}
				renderFormattedSubfinderResponse(cmd.OutOrStdout(), resp)
				return nil
			}

			collector := newStreamCollector()
			scanID, err := httpClient.StreamSubfinder(ctx, request, func(line string) {
				_, _ = fmt.Fprintln(cmd.OutOrStdout(), line)
				collector.consumeLine(line)
			})
			if err != nil {
				if ctx.Err() != nil {
					if strings.TrimSpace(scanID) != "" {
						cancelCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
						defer cancel()
						if cancelErr := httpClient.CancelSubfinder(cancelCtx, scanID); cancelErr != nil {
							_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "cancel request failed for scan_id=%s: %v\n", scanID, cancelErr)
						} else {
							_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "scan cancel requested for scan_id=%s\n", scanID)
						}
					}
					return nil
				}
				return err
			}

			_, _ = fmt.Fprintln(cmd.OutOrStdout())
			renderFormattedSubfinderResponse(cmd.OutOrStdout(), &client.SubfinderResponse{
				ScanID:  scanID,
				Results: collector.results(),
			})
			return nil
		},
	}

	cmd.Flags().StringVarP(&domain, "domain", "d", "", "Target domain, for example target.com")
	cmd.Flags().BoolVar(&json, "json", false, "Use non-streaming JSON endpoint instead of live terminal output")
	_ = cmd.MarkFlagRequired("domain")

	return cmd
}

type streamCollector struct {
	bySubdomain map[string]client.SubdomainScanResult
}

func newStreamCollector() *streamCollector {
	return &streamCollector{
		bySubdomain: make(map[string]client.SubdomainScanResult),
	}
}

func (c *streamCollector) consumeLine(line string) {
	result, ok := parseStreamResultLine(line)
	if !ok {
		return
	}
	c.bySubdomain[result.Subdomain] = *result
}

func (c *streamCollector) results() []client.SubdomainScanResult {
	out := make([]client.SubdomainScanResult, 0, len(c.bySubdomain))
	for _, value := range c.bySubdomain {
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Subdomain < out[j].Subdomain
	})
	return out
}

func parseStreamResultLine(line string) (*client.SubdomainScanResult, bool) {
	matches := streamResultPattern.FindStringSubmatch(strings.TrimSpace(line))
	if len(matches) != 7 {
		return nil, false
	}

	statusCode, err := strconv.Atoi(matches[3])
	if err != nil {
		return nil, false
	}

	title, err := strconv.Unquote(matches[5])
	if err != nil {
		title = strings.Trim(matches[5], `"`)
	}

	rawTech := strings.TrimSpace(matches[6])
	var technologies []string
	if rawTech != "" && rawTech != "-" {
		parts := strings.Split(rawTech, ",")
		technologies = make([]string, 0, len(parts))
		for _, part := range parts {
			value := strings.TrimSpace(part)
			if value != "" {
				technologies = append(technologies, value)
			}
		}
	}

	ip := strings.TrimSpace(matches[4])
	if ip == "-" {
		ip = ""
	}

	return &client.SubdomainScanResult{
		Subdomain:    matches[2],
		IsAlive:      matches[1] == "UP",
		StatusCode:   statusCode,
		IP:           ip,
		Title:        title,
		Technologies: technologies,
	}, true
}

func renderFormattedSubfinderResponse(out io.Writer, resp *client.SubfinderResponse) {
	_, _ = fmt.Fprintf(out, "scan_id: %s\n", resp.ScanID)
	if len(resp.Results) == 0 {
		_, _ = fmt.Fprintln(out, "No subdomains found.")
		return
	}

	writer := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(writer, "SUBDOMAIN\tALIVE\tSTATUS\tIP\tTITLE\tTECH")
	for _, result := range resp.Results {
		ip := strings.TrimSpace(result.IP)
		if ip == "" {
			ip = "-"
		}
		title := strings.TrimSpace(result.Title)
		if title == "" {
			title = "-"
		}
		tech := "-"
		if len(result.Technologies) > 0 {
			tech = strings.Join(result.Technologies, ",")
		}

		_, _ = fmt.Fprintf(
			writer,
			"%s\t%t\t%d\t%s\t%s\t%s\n",
			result.Subdomain,
			result.IsAlive,
			result.StatusCode,
			ip,
			title,
			tech,
		)
	}
	_ = writer.Flush()
}
