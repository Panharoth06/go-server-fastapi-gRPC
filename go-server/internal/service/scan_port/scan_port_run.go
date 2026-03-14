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
	if err != nil {
		log.Printf("scan_port: database unavailable, skipping persistence: %v", err)
		store = nil
	}

	for _, host := range hosts {
		expectedResultCount := len(ports)
		if expectedResultCount == 0 {
			expectedResultCount = portPersistWorkerSize
		}

		persistence := newPortScanPersistence(ctx, store, host, userID, expectedResultCount)
		if err := enumeratePorts(ctx, host, scanID, ports, sender, persistence); err != nil {
			persistence.closeAndWait()
			return err
		}
		persistence.closeAndWait()
		if err := ctx.Err(); err != nil {
			return canceledScanError()
		}
		if err := sender.finalError(); err != nil {
			if isCanceledError(ctx, err) {
				return canceledScanError()
			}
			return status.Errorf(codes.Internal, "stream send failed: %v", err)
		}
	}

	return nil
}

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
			case <-ctx.Done():
				return
			default:
			}

			if hr == nil {
				return
			}

			responseHost := strings.TrimSpace(hr.Host)
			if responseHost == "" {
				responseHost = strings.TrimSpace(hr.IP)
			}

			for _, port := range hr.Ports {
				if port == nil {
					continue
				}

				observation := &portObservation{
					host: responseHost,
					port: port.Port,
				}
				if port.Service != nil {
					observation.serviceName = port.Service.Name
					observation.serviceVersion = port.Service.Version
					observation.operatingSystem = port.Service.OSType
				}
				observations = append(observations, observation)
			}
		},
	}

	if len(requestedPorts) > 0 {
		naabuOpts.Ports = strings.Join(requestedPorts, ",")
	} else {
		naabuOpts.TopPorts = "1000"
	}

	if err := naabuOpts.ValidateOptions(); err != nil {
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
		if isCanceledError(ctx, err) {
			return canceledScanError()
		}
		return status.Errorf(codes.Internal, "failed to run port enumeration: %v", err)
	}

	if err := ctx.Err(); err != nil {
		return canceledScanError()
	}

	if len(observations) == 0 {
		return nil
	}

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

func (s *streamSender) send(resp *scan_port.ScanPortsResponse) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.err != nil {
		return
	}

	s.err = s.stream.Send(resp)
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

func detectHostOperatingSystem(hr *result.HostResult) string {
	if hr == nil || hr.OS == nil {
		return ""
	}

	if details := strings.TrimSpace(hr.OS.OSDetails); details != "" {
		return details
	}
	if running := strings.TrimSpace(hr.OS.Running); running != "" {
		return running
	}
	return strings.TrimSpace(hr.OS.OSCPE)
}

func enrichObservationsWithNmap(ctx context.Context, host string, observations []*portObservation) error {
	if len(observations) == 0 {
		return nil
	}

	ports := make([]string, 0, len(observations))
	for _, observation := range observations {
		if observation == nil {
			continue
		}
		ports = append(ports, strconv.Itoa(observation.port))
	}
	if len(ports) == 0 {
		return nil
	}

	includeOS := privileges.IsPrivileged
	useSudo := false
	if !includeOS && useSudoForNmapOS() {
		includeOS = true
		useSudo = true
	}
	if !includeOS {
		log.Printf("scan_port: nmap OS detection skipped for %s: run the server as root or set SCAN_PORT_NMAP_USE_SUDO=true with passwordless sudo", host)
	}

	run, warnings, err := runNmapEnrichment(ctx, host, ports, includeOS, useSudo)
	if err != nil && includeOS && !isCanceledError(ctx, err) {
		log.Printf("scan_port: retrying nmap enrichment without OS detection for %s: %v", host, err)
		run, warnings, err = runNmapEnrichment(ctx, host, ports, false, false)
	}
	if warnings != nil {
		for _, warning := range *warnings {
			log.Printf("scan_port: nmap warning (%s): %s", host, warning)
		}
	}
	if err != nil {
		return err
	}

	mergeNmapObservations(run, observations)
	return nil
}

func runNmapEnrichment(ctx context.Context, host string, ports []string, includeOS bool, useSudo bool) (*nmap.Run, *[]string, error) {
	args := []string{"-Pn", "-sV", "-T3"}
	if includeOS {
		args = append(args, "-O")
	}

	options := []nmap.Option{
		nmap.WithTargets(host),
		nmap.WithPorts(strings.Join(ports, ",")),
		nmap.WithCustomArguments(args...),
	}
	if useSudo {
		sudoPath, nmapPath, err := resolveSudoNmapPaths()
		if err != nil {
			return nil, nil, err
		}
		options = append([]nmap.Option{
			nmap.WithBinaryPath(sudoPath),
			nmap.WithCustomArguments("-n", nmapPath),
		}, options...)
	}

	scanner, err := nmap.NewScanner(ctx, options...)
	if err != nil {
		return nil, nil, err
	}

	return scanner.Run()
}

func useSudoForNmapOS() bool {
	value := strings.TrimSpace(os.Getenv("SCAN_PORT_NMAP_USE_SUDO"))
	switch strings.ToLower(value) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

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

func mergeNmapObservations(run *nmap.Run, observations []*portObservation) {
	if run == nil || len(run.Hosts) == 0 || len(observations) == 0 {
		return
	}

	hostOperatingSystem := extractNmapHostOperatingSystem(run.Hosts[0])
	serviceByPort := make(map[int]nmap.Service)
	for _, host := range run.Hosts {
		for _, port := range host.Ports {
			if port.State.State != "open" {
				continue
			}
			serviceByPort[int(port.ID)] = port.Service
		}
	}

	for _, observation := range observations {
		if observation == nil {
			continue
		}
		if hostOperatingSystem != "" {
			observation.operatingSystem = hostOperatingSystem
		}
		if service, ok := serviceByPort[observation.port]; ok {
			if name := strings.TrimSpace(service.Name); name != "" {
				observation.serviceName = name
			}
			if version := strings.TrimSpace(service.Version); version != "" {
				observation.serviceVersion = version
			}
			if observation.operatingSystem == "" {
				observation.operatingSystem = strings.TrimSpace(service.OSType)
			}
		}
	}
}

func extractNmapHostOperatingSystem(host nmap.Host) string {
	if len(host.OS.Matches) == 0 {
		return ""
	}

	best := host.OS.Matches[0]
	if len(best.Classes) > 0 {
		details := strings.TrimSpace(strings.TrimSpace(best.Classes[0].Vendor) + " " + strings.TrimSpace(best.Classes[0].OSGeneration))
		if details != "" {
			return details
		}
	}
	return strings.TrimSpace(best.Name)
}
