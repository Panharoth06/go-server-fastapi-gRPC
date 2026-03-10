package service

import (
	"context"
	"strings"

	"go-server/gen/scan_subdomain"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// This file exposes the gRPC entrypoints for subdomain scanning.
// It keeps request validation and RPC-level control flow in one place,
// while delegating scan execution, active-scan tracking, and persistence
// to the helper files in this package.

type scanSubdomainServer struct {
	scan_subdomain.UnimplementedSubdomainScannerServer
}

// NewScanSubdomainServer builds the gRPC service implementation that gets
// registered by the application bootstrap code.
func NewScanSubdomainServer() scan_subdomain.SubdomainScannerServer {
	return &scanSubdomainServer{}
}

// ScanAndCheck validates the incoming request, ensures the scan has an ID,
// registers it as cancellable, and then hands execution to the scan runner.
func (s *scanSubdomainServer) ScanAndCheck(
	req *scan_subdomain.ScanRequest,
	stream scan_subdomain.SubdomainScanner_ScanAndCheckServer,
) error {
	if req == nil {
		return status.Error(codes.InvalidArgument, "request cannot be empty")
	}

	domain := strings.TrimSpace(req.Domain)
	if domain == "" {
		return status.Error(codes.InvalidArgument, "domain cannot be empty")
	}

	userID := strings.TrimSpace(req.UserId)
	scanID := normalizeScanID(req.ScanId)
	if scanID == "" {
		scanID = uuid.NewString()
	}

	ctx, cancel := context.WithCancel(stream.Context())
	if err := registerActiveScan(scanID, userID, cancel); err != nil {
		cancel()
		return err
	}
	defer func() {
		unregisterActiveScan(scanID)
		cancel()
	}()

	return runSubdomainScan(ctx, cancel, stream, domain, userID, scanID)
}

// CancelScan looks up a running scan, verifies that the requesting user owns
// it when ownership is set, and triggers the stored cancel function once.
func (s *scanSubdomainServer) CancelScan(
	ctx context.Context,
	req *scan_subdomain.CancelScanRequest,
) (*scan_subdomain.CancelScanResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request cannot be empty")
	}

	scanID := normalizeScanID(req.ScanId)
	if scanID == "" {
		return nil, status.Error(codes.InvalidArgument, "scan_id cannot be empty")
	}

	scan, ok := lookupActiveScan(scanID)
	if !ok {
		return nil, status.Error(codes.NotFound, "scan not found")
	}

	requestUserID := strings.TrimSpace(req.UserId)
	if scan.userID != "" && requestUserID != scan.userID {
		return nil, status.Error(codes.PermissionDenied, "scan belongs to another user")
	}

	scan.cancelOnce.Do(scan.cancel)
	return &scan_subdomain.CancelScanResponse{
		ScanId:    scanID,
		Cancelled: true,
		Message:   "cancel requested",
	}, nil
}
