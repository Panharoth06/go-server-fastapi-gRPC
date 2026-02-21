package service

import (
	"context"
	"github.com/projectdiscovery/goflags"
	httpxrunner "github.com/projectdiscovery/httpx/runner"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
	"go-server/gen/scan_subdomain"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"sync"
)

type scanSubdomainServer struct {
	scan_subdomain.UnimplementedSubdomainScannerServer
}

func NewScanSubdomainServer() scan_subdomain.SubdomainScannerServer {
	return &scanSubdomainServer{}
}

func (s *scanSubdomainServer) ScanAndCheck(
	req *scan_subdomain.ScanRequest,
	stream scan_subdomain.SubdomainScanner_ScanAndCheckServer,
) error {
	if req == nil || req.Domain == "" {
		return status.Error(codes.InvalidArgument, "domain cannot be empty")
	}

	var (
		mu         sync.Mutex
		subdomains []string
		seen       = map[string]struct{}{}
	)

	subfinderOpts := &runner.Options{
		Threads:            10,
		Timeout:            30,
		MaxEnumerationTime: 10,
		ResultCallback: func(result *resolve.HostEntry) {
			if result == nil || result.Host == "" {
				return
			}
			mu.Lock()
			if _, ok := seen[result.Host]; !ok {
				seen[result.Host] = struct{}{}
				subdomains = append(subdomains, result.Host)
			}
			mu.Unlock()
		},
	}

	subfinderRunner, err := runner.NewRunner(subfinderOpts)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to create subfinder runner: %v", err)
	}
	if _, err := subfinderRunner.EnumerateSingleDomainWithCtx(context.Background(), req.Domain, nil); err != nil {
		return status.Errorf(codes.Internal, "subfinder failed: %v", err)
	}

	if len(subdomains) == 0 {
		return nil
	}

	var streamErr error
	httpxOptions := &httpxrunner.Options{
		Methods:         "GET",
		InputTargetHost: goflags.StringSlice(subdomains),
		StatusCode:      true,
		OutputIP:        true,
		TechDetect:      true,
		ExtractTitle:    true,
		Timeout:         10,
		Retries:         2,
		NoColor:         true,
		Silent:          true,
		OnResult: func(r httpxrunner.Result) {
			mu.Lock()
			defer mu.Unlock()
			if streamErr != nil {
				return
			}
			streamErr = stream.Send(&scan_subdomain.ScanResponse{
				Subdomain:    r.Input,
				IsAlive:      r.StatusCode > 0 && !r.Failed,
				StatusCode:   int32(r.StatusCode),
				Title:        r.Title,
				Ip:           r.HostIP,
				Technologies: r.Technologies,
			})
		},
	}
	if err := httpxOptions.ValidateOptions(); err != nil {
		return status.Errorf(codes.Internal, "invalid httpx options: %v", err)
	}

	httpxRunner, err := httpxrunner.New(httpxOptions)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to create httpx runner: %v", err)
	}
	defer httpxRunner.Close()

	httpxRunner.RunEnumeration()

	if streamErr != nil {
		return status.Errorf(codes.Internal, "stream send failed: %v", streamErr)
	}
	return nil
}
