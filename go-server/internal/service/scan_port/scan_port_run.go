package scanport

import (
	"context"
	"log"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"

	"go-server/gen/scan_port"

	"github.com/Ullaakut/nmap/v3"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/naabu/v2/pkg/privileges"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	naaburunner "github.com/projectdiscovery/naabu/v2/pkg/runner"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type streamSender struct {
	cancel context.CancelCauseFunc
	mu     sync.Mutex
	err    error
	stream scan_port.ScanPortService_ScanPortsServer
}

type portObservation struct {
	host            string
	port            int
	serviceName     string
	serviceVersion  string
	operatingSystem string
}

// runPortScan executes host-by-host scanning, streaming, and background persistence.
func runPortScan(
	ctx context.Context,
	cancel context.CancelCauseFunc,
	stream scan_port.ScanPortService_ScanPortsServer,
	scanID string,
	userID string,
	hosts []string,
	ports []string,
) error {
	sender := &streamSender{
		cancel: cancel,
		stream: stream,
	}

	store, err := getStore()
	// Scan should still run even when persistence is temporarily unavailable.
	if err != nil {
		log.Printf("scan_port: database unavailable, skipping persistence: %v", err)
		store = nil
	}

	for _, host := range hosts {
		expectedResultCount := len(ports)
		// With top-ports mode, keep a safe default worker count.
		if expectedResultCount == 0 {
			expectedResultCount = portPersistWorkerSize
		}

		persistence := newPortScanPersistence(ctx, store, host, userID, expectedResultCount)
		// Any enumeration error ends this host scan immediately.
		if err := enumeratePorts(ctx, host, scanID, ports, sender, persistence); err != nil {
			persistence.closeAndWait()
			return err
		}
		persistence.closeAndWait()
		// Context cancellation should win over post-processing work.
		if err := ctx.Err(); err != nil {
			return canceledScanError()
		}
		// Convert stream transport failures into a stable gRPC error.
		if err := sender.finalError(); err != nil {
			if isCanceledError(ctx, err) {
				return canceledScanError()
			}
			return status.Errorf(codes.Internal, "stream send failed: %v", err)
		}
	}

	return nil
}

// enumeratePorts runs naabu against one host, enriches results, streams them, and queues DB writes.
func enumeratePorts(
	ctx context.Context,
	host string,
	scanID string,
	requestedPorts []string,
	sender *streamSender,
	persistence *portScanPersistence,
) error {
	var observations []*portObservation

	naabuOpts := &naaburunner.Options{
		Host:          goflags.StringSlice{host},
		ScanType:      naaburunner.ConnectScan,
		Rate:          naaburunner.DefaultRateConnectScan,
		Retries:       naaburunner.DefaultRetriesConnectScan,
		Threads:       naaburunner.DefaultThreadsNum,
		Timeout:       naaburunner.DefaultPortTimeoutConnectScan,
		DisableStdout: true,
		NoColor:       true,
		Silent:        true,
		OnResult: func(hr *result.HostResult) {
			select {
			// Stop processing callback results once the request is canceled.
			case <-ctx.Done():
				return
			default:
			}

			// Defensive guard for empty callback payloads.
			if hr == nil {
				return
			}

			responseHost := strings.TrimSpace(hr.Host)
			// Fall back to IP if host label is empty.
			if responseHost == "" {
				responseHost = strings.TrimSpace(hr.IP)
			}

			for _, port := range hr.Ports {
				// Some callbacks may include nil entries.
				if port == nil {
					continue
				}

				observation := &portObservation{
					host: responseHost,
					port: port.Port,
				}
				// Service metadata is optional in naabu output.
				if port.Service != nil {
					observation.serviceName = port.Service.Name
					observation.serviceVersion = port.Service.Version
					observation.operatingSystem = port.Service.OSType
				}
				observations = append(observations, observation)
			}
		},
	}

	// Use requested ports when provided, otherwise run a top-ports scan.
	if len(requestedPorts) > 0 {
		naabuOpts.Ports = strings.Join(requestedPorts, ",")
	} else {
		naabuOpts.TopPorts = "1000"
	}

	if err := naabuOpts.ValidateOptions(); err != nil {
		// Bad user port input is an invalid-argument error.
		if len(requestedPorts) > 0 {
			return status.Errorf(codes.InvalidArgument, "invalid port selection: %v", err)
		}
		return status.Errorf(codes.Internal, "invalid naabu options: %v", err)
	}

	naabuRunner, err := naaburunner.NewRunner(naabuOpts)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to create naabu runner: %v", err)
	}
	defer naabuRunner.Close()

	if err := naabuRunner.RunEnumeration(ctx); err != nil {
		// Report canceled scans with a consistent canceled status.
		if isCanceledError(ctx, err) {
			return canceledScanError()
		}
		return status.Errorf(codes.Internal, "failed to run port enumeration: %v", err)
	}

	// Scan may finish after caller cancellation; normalize that path.
	if err := ctx.Err(); err != nil {
		return canceledScanError()
	}

	// No open ports means nothing to stream or persist.
	if len(observations) == 0 {
		return nil
	}

	// Nmap enrichment failure is non-fatal; base naabu results are still useful.
	if err := enrichObservationsWithNmap(ctx, host, observations); err != nil && !isCanceledError(ctx, err) {
		log.Printf("scan_port: nmap enrichment failed (%s): %v", host, err)
	}

	sort.Slice(observations, func(i, j int) bool {
		return observations[i].port < observations[j].port
	})

	for _, observation := range observations {
		resp := &scan_port.ScanPortsResponse{
			Host:            observation.host,
			Port:            strconv.Itoa(observation.port),
			ScanId:          scanID,
			ServiceName:     observation.serviceName,
			ServiceVersion:  observation.serviceVersion,
			OperatingSystem: observation.operatingSystem,
		}

		sender.send(resp)
		// Stop on first stream error to avoid wasting scan work.
		if sender.finalError() != nil {
			return nil
		}

		persistence.enqueue(openPortPersistTask{
			port:            observation.port,
			serviceName:     observation.serviceName,
			serviceVersion:  observation.serviceVersion,
			operatingSystem: observation.operatingSystem,
		})
	}

	return nil
}

// send serializes writes to the gRPC stream and records the first send error.
func (s *streamSender) send(resp *scan_port.ScanPortsResponse) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Once an error is recorded, all future sends are ignored.
	if s.err != nil {
		return
	}

	s.err = s.stream.Send(resp)
	// Cancel the scan so scanner goroutines stop quickly.
	if s.err != nil {
		s.cancel(s.err)
	}
}

// finalError returns the first stream send error recorded during enumeration.
func (s *streamSender) finalError() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

// detectHostOperatingSystem picks the most useful OS field from naabu output.
func detectHostOperatingSystem(hr *result.HostResult) string {
	// OS block may be absent for many targets.
	if hr == nil || hr.OS == nil {
		return ""
	}

	// Prefer richer fingerprint details when available.
	if details := strings.TrimSpace(hr.OS.OSDetails); details != "" {
		return details
	}
	// Fall back to generic running OS label.
	if running := strings.TrimSpace(hr.OS.Running); running != "" {
		return running
	}
	return strings.TrimSpace(hr.OS.OSCPE)
}

// enrichObservationsWithNmap adds service/version and optional OS data to port observations.
func enrichObservationsWithNmap(ctx context.Context, host string, observations []*portObservation) error {
	// Nothing to enrich when list is empty.
	if len(observations) == 0 {
		return nil
	}

	ports := make([]string, 0, len(observations))
	for _, observation := range observations {
		// Skip defensive nil entries.
		if observation == nil {
			continue
		}
		ports = append(ports, strconv.Itoa(observation.port))
	}
	// Bail out if no valid ports were collected.
	if len(ports) == 0 {
		return nil
	}

	includeOS := privileges.IsPrivileged
	useSudo := false
	// Enable sudo fallback when OS detection is requested without root privileges.
	if !includeOS && useSudoForNmapOS() {
		includeOS = true
		useSudo = true
	}
	// Log skipped OS detection so operators know how to enable it.
	if !includeOS {
		log.Printf("scan_port: nmap OS detection skipped for %s: run the server as root or set SCAN_PORT_NMAP_USE_SUDO=true with passwordless sudo", host)
	}

	run, warnings, err := runNmapEnrichment(ctx, host, ports, includeOS, useSudo)
	// Retry without OS detection when privileged mode fails.
	if err != nil && includeOS && !isCanceledError(ctx, err) {
		log.Printf("scan_port: retrying nmap enrichment without OS detection for %s: %v", host, err)
		run, warnings, err = runNmapEnrichment(ctx, host, ports, false, false)
	}
	// Nmap warnings are informational and should not fail the scan.
	if warnings != nil {
		for _, warning := range *warnings {
			log.Printf("scan_port: nmap warning (%s): %s", host, warning)
		}
	}
	// Propagate fatal nmap errors after retry logic.
	if err != nil {
		return err
	}

	mergeNmapObservations(run, observations)
	return nil
}

// runNmapEnrichment executes nmap with typed options and optional sudo wrapper.
func runNmapEnrichment(ctx context.Context, host string, ports []string, includeOS bool, useSudo bool) (*nmap.Run, *[]string, error) {
	options := []nmap.Option{
		nmap.WithTargets(host),
		nmap.WithPorts(strings.Join(ports, ",")),
		nmap.WithSkipHostDiscovery(),
		nmap.WithServiceInfo(),
		nmap.WithTimingTemplate(nmap.TimingNormal),
	}
	// Add OS detection only when explicitly requested.
	if includeOS {
		options = append(options, nmap.WithOSDetection())
	}
	// Use a temporary wrapper to run nmap through passwordless sudo.
	if useSudo {
		sudoPath, nmapPath, err := resolveSudoNmapPaths()
		if err != nil {
			return nil, nil, err
		}
		sudoWrapperPath, cleanup, err := createSudoNmapWrapper(sudoPath, nmapPath)
		if err != nil {
			return nil, nil, err
		}
		defer cleanup()

		options = append(options, nmap.WithBinaryPath(sudoWrapperPath))
	}

	scanner, err := nmap.NewScanner(ctx, options...)
	if err != nil {
		return nil, nil, err
	}

	return scanner.Run()
}

// useSudoForNmapOS reads the feature flag for sudo-based OS detection.
func useSudoForNmapOS() bool {
	value := strings.TrimSpace(os.Getenv("SCAN_PORT_NMAP_USE_SUDO"))
	switch strings.ToLower(value) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// resolveSudoNmapPaths ensures both sudo and nmap binaries are available.
func resolveSudoNmapPaths() (string, string, error) {
	sudoPath, err := exec.LookPath("sudo")
	if err != nil {
		return "", "", err
	}
	nmapPath, err := exec.LookPath("nmap")
	if err != nil {
		return "", "", err
	}
	return sudoPath, nmapPath, nil
}

// createSudoNmapWrapper builds a temporary executable that runs nmap via sudo -n.
func createSudoNmapWrapper(sudoPath string, nmapPath string) (string, func(), error) {
	wrapper, err := os.CreateTemp("", "scan-port-sudo-nmap-*")
	if err != nil {
		return "", nil, err
	}

	wrapperPath := wrapper.Name()
	cleanup := func() {
		_ = os.Remove(wrapperPath)
	}

	script := "#!/bin/sh\nexec " + strconv.Quote(sudoPath) + " -n " + strconv.Quote(nmapPath) + " \"$@\"\n"
	if _, err := wrapper.WriteString(script); err != nil {
		_ = wrapper.Close()
		cleanup()
		return "", nil, err
	}
	if err := wrapper.Close(); err != nil {
		cleanup()
		return "", nil, err
	}
	if err := os.Chmod(wrapperPath, 0o700); err != nil {
		cleanup()
		return "", nil, err
	}

	return wrapperPath, cleanup, nil
}

// mergeNmapObservations overlays nmap findings onto naabu observations by port.
func mergeNmapObservations(run *nmap.Run, observations []*portObservation) {
	// Need at least one scanned host and one observation to merge.
	if run == nil || len(run.Hosts) == 0 || len(observations) == 0 {
		return
	}

	hostOperatingSystem := extractNmapHostOperatingSystem(run.Hosts[0])
	serviceByPort := make(map[int]nmap.Service)
	for _, host := range run.Hosts {
		for _, port := range host.Ports {
			// Keep only open ports for response enrichment.
			if port.State.State != "open" {
				continue
			}
			serviceByPort[int(port.ID)] = port.Service
		}
	}

	for _, observation := range observations {
		// Skip nil entries to keep merge loop safe.
		if observation == nil {
			continue
		}
		// Host-level OS fingerprint has priority when present.
		if hostOperatingSystem != "" {
			observation.operatingSystem = hostOperatingSystem
		}
		if service, ok := serviceByPort[observation.port]; ok {
			// Keep original value when nmap field is empty.
			if name := strings.TrimSpace(service.Name); name != "" {
				observation.serviceName = name
			}
			if version := strings.TrimSpace(service.Version); version != "" {
				observation.serviceVersion = version
			}
			// Use service OSType only if host OS was not detected.
			if observation.operatingSystem == "" {
				observation.operatingSystem = strings.TrimSpace(service.OSType)
			}
		}
	}
}

// extractNmapHostOperatingSystem returns the best host-level OS label from nmap matches.
func extractNmapHostOperatingSystem(host nmap.Host) string {
	// No OS match means no host-level OS information.
	if len(host.OS.Matches) == 0 {
		return ""
	}

	best := host.OS.Matches[0]
	// Prefer vendor + generation when nmap class data exists.
	if len(best.Classes) > 0 {
		details := strings.TrimSpace(strings.TrimSpace(best.Classes[0].Vendor) + " " + strings.TrimSpace(best.Classes[0].OSGeneration))
		if details != "" {
			return details
		}
	}
	return strings.TrimSpace(best.Name)
}
