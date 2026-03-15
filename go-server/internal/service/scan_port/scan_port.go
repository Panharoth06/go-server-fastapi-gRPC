package scanport

import (
	"context"
	"strings"

	"go-server/gen/scan_port"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type scanPortServer struct {
	scan_port.UnimplementedScanPortServiceServer
}

// NewScanPortServer builds the gRPC service implementation that gets
// registered by the application bootstrap code.
func NewScanPortServer() scan_port.ScanPortServiceServer {
	return &scanPortServer{}
}

// ScanPorts validates request fields, registers scan lifecycle state,
// and delegates actual execution to the scan runner.
func (s *scanPortServer) ScanPorts(
	req *scan_port.ScanPortsRequest,
	stream scan_port.ScanPortService_ScanPortsServer,
) error {
	// Reject nil requests to avoid dereferencing empty payloads.
	if req == nil {
		return status.Error(codes.InvalidArgument, "request cannot be empty")
	}

	hosts := make([]string, 0, len(req.Hosts))
	for _, value := range req.Hosts {
		host := strings.TrimSpace(value)
		// Every host entry must be non-empty after trimming spaces.
		if host == "" {
			return status.Error(codes.InvalidArgument, "host cannot be empty")
		}
		hosts = append(hosts, host)
	}
	// The scan requires at least one target host.
	if len(hosts) == 0 {
		return status.Error(codes.InvalidArgument, "at least one host is required")
	}

	ports := make([]string, 0, len(req.Port))
	for _, value := range req.Port {
		port := strings.TrimSpace(value)
		// Reject blank port entries so the scan options stay valid.
		if port == "" {
			return status.Error(codes.InvalidArgument, "port cannot be empty")
		}
		ports = append(ports, port)
	}

	userID := strings.TrimSpace(req.UserId)
	scanID := normalizeScanID(req.ScanId)
	// Generate a scan ID when the client does not provide one.
	if scanID == "" {
		scanID = uuid.NewString()
	}

	ctx, cancel := context.WithCancelCause(stream.Context())
	// Prevent duplicate active scans with the same ID.
	if err := registerActiveScanPort(scanID, userID, cancel); err != nil {
		cancel(err)
		return err
	}
	defer func() {
		unregisterActiveScanPort(scanID)
		cancel(nil)
	}()

	return runPortScan(ctx, cancel, stream, scanID, userID, hosts, ports)
}

// CancelScan looks up a running scan, verifies that the requesting user owns
// it when ownership is set, and triggers the stored cancel function once.
func (s *scanPortServer) CancelScan(
	ctx context.Context,
	req *scan_port.CancelScanRequest,
) (*scan_port.CancelScanResponse, error) {
	// Cancel request itself must exist.
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request cannot be empty")
	}

	scanID := normalizeScanID(req.ScanId)
	// scan_id is required to locate the running scan.
	if scanID == "" {
		return nil, status.Error(codes.InvalidArgument, "scan_id cannot be empty")
	}

	scan, ok := lookupActiveScanPort(scanID)
	// If the scan is not active anymore, nothing can be canceled.
	if !ok {
		return nil, status.Error(codes.NotFound, "scan not found")
	}

	requestUserID := strings.TrimSpace(req.UserId)
	// Enforce ownership when the scan was created with a user ID.
	if scan.userID != "" && requestUserID != scan.userID {
		return nil, status.Error(codes.PermissionDenied, "scan belongs to another user")
	}

	scan.cancelOnce.Do(func() {
		scan.cancel(context.Canceled)
	})

	return &scan_port.CancelScanResponse{
		ScanId:    scanID,
		Cancelled: true,
		Message:   "cancel requested",
	}, nil
}
