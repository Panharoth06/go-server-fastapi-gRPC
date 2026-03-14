package scanport

import (
	"context"
	"errors"
	"testing"

	"go-server/gen/scan_port"

	"github.com/Ullaakut/nmap/v3"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestCancelScanCancelsRegisteredScan(t *testing.T) {
	t.Cleanup(func() {
		unregisterActiveScanPort("scan-1")
	})

	ctx, cancel := context.WithCancelCause(context.Background())
	if err := registerActiveScanPort("scan-1", "user-1", cancel); err != nil {
		t.Fatalf("registerActiveScanPort() error = %v", err)
	}

	server := &scanPortServer{}
	resp, err := server.CancelScan(context.Background(), &scan_port.CancelScanRequest{
		ScanId: "scan-1",
		UserId: "user-1",
	})
	if err != nil {
		t.Fatalf("CancelScan() error = %v", err)
	}
	if !resp.Cancelled {
		t.Fatalf("CancelScan() cancelled = false, want true")
	}
	if resp.ScanId != "scan-1" {
		t.Fatalf("CancelScan() scan_id = %q, want %q", resp.ScanId, "scan-1")
	}

	<-ctx.Done()
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatalf("context err = %v, want %v", ctx.Err(), context.Canceled)
	}
}

func TestCancelScanRejectsDifferentUser(t *testing.T) {
	t.Cleanup(func() {
		unregisterActiveScanPort("scan-2")
	})

	ctx, cancel := context.WithCancelCause(context.Background())
	if err := registerActiveScanPort("scan-2", "owner-1", cancel); err != nil {
		t.Fatalf("registerActiveScanPort() error = %v", err)
	}

	server := &scanPortServer{}
	_, err := server.CancelScan(context.Background(), &scan_port.CancelScanRequest{
		ScanId: "scan-2",
		UserId: "other-user",
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("CancelScan() code = %v, want %v", status.Code(err), codes.PermissionDenied)
	}
	select {
	case <-ctx.Done():
		t.Fatal("scan context canceled unexpectedly")
	default:
	}
}

func TestDetectHostOperatingSystem(t *testing.T) {
	t.Run("prefers os details", func(t *testing.T) {
		got := detectHostOperatingSystem(&result.HostResult{
			OS: &result.OSFingerprint{
				OSDetails: "Linux 6.x",
				Running:   "Linux",
				OSCPE:     "cpe:/o:linux:linux_kernel",
			},
		})
		if got != "Linux 6.x" {
			t.Fatalf("detectHostOperatingSystem() = %q, want %q", got, "Linux 6.x")
		}
	})

	t.Run("falls back to running then cpe", func(t *testing.T) {
		got := detectHostOperatingSystem(&result.HostResult{
			OS: &result.OSFingerprint{
				Running: "Windows",
				OSCPE:   "cpe:/o:microsoft:windows",
			},
		})
		if got != "Windows" {
			t.Fatalf("detectHostOperatingSystem() = %q, want %q", got, "Windows")
		}

		got = detectHostOperatingSystem(&result.HostResult{
			OS: &result.OSFingerprint{
				OSCPE: "cpe:/o:freebsd:freebsd",
			},
		})
		if got != "cpe:/o:freebsd:freebsd" {
			t.Fatalf("detectHostOperatingSystem() = %q, want %q", got, "cpe:/o:freebsd:freebsd")
		}
	})

	t.Run("handles missing os fingerprint", func(t *testing.T) {
		if got := detectHostOperatingSystem(nil); got != "" {
			t.Fatalf("detectHostOperatingSystem(nil) = %q, want empty string", got)
		}
		if got := detectHostOperatingSystem(&result.HostResult{}); got != "" {
			t.Fatalf("detectHostOperatingSystem() = %q, want empty string", got)
		}
	})
}

func TestMergeNmapObservations(t *testing.T) {
	observations := []*portObservation{
		{
			host:            "example.com",
			port:            22,
			serviceName:     "ssh",
			serviceVersion:  "old",
			operatingSystem: "service-os",
		},
		{
			host: "example.com",
			port: 80,
		},
	}

	run := &nmap.Run{
		Hosts: []nmap.Host{
			{
				OS: nmap.OS{
					Matches: []nmap.OSMatch{
						{
							Name: "Linux 6.X",
							Classes: []nmap.OSClass{
								{
									Vendor:       "Linux",
									OSGeneration: "6.X",
								},
							},
						},
					},
				},
				Ports: []nmap.Port{
					{
						ID:       22,
						Protocol: "tcp",
						State:    nmap.State{State: "open"},
						Service: nmap.Service{
							Name:    "openssh",
							Version: "9.7",
							OSType:  "linux",
						},
					},
					{
						ID:       80,
						Protocol: "tcp",
						State:    nmap.State{State: "open"},
						Service: nmap.Service{
							Name:    "http",
							Version: "Apache",
						},
					},
				},
			},
		},
	}

	mergeNmapObservations(run, observations)

	if observations[0].serviceName != "openssh" {
		t.Fatalf("serviceName = %q, want %q", observations[0].serviceName, "openssh")
	}
	if observations[0].serviceVersion != "9.7" {
		t.Fatalf("serviceVersion = %q, want %q", observations[0].serviceVersion, "9.7")
	}
	if observations[0].operatingSystem != "Linux 6.X" {
		t.Fatalf("operatingSystem = %q, want %q", observations[0].operatingSystem, "Linux 6.X")
	}
	if observations[1].operatingSystem != "Linux 6.X" {
		t.Fatalf("operatingSystem = %q, want %q", observations[1].operatingSystem, "Linux 6.X")
	}
}

func TestUseSudoForNmapOS(t *testing.T) {
	t.Setenv("SCAN_PORT_NMAP_USE_SUDO", "true")
	if !useSudoForNmapOS() {
		t.Fatal("useSudoForNmapOS() = false, want true")
	}

	t.Setenv("SCAN_PORT_NMAP_USE_SUDO", "0")
	if useSudoForNmapOS() {
		t.Fatal("useSudoForNmapOS() = true, want false")
	}
}
