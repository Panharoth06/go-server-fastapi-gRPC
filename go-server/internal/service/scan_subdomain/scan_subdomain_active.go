package scansubdomain

import (
	"context"
	"errors"
	"strings"
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// This file manages the in-memory registry of active subdomain scans.
// It is responsible for tracking which scans are cancellable, guarding
// ownership checks, and normalizing scan lifecycle error handling.

type activeScan struct {
	userID     string
	cancel     context.CancelFunc
	cancelOnce sync.Once
}

var activeSubdomainMap sync.Map

// registerActiveScan stores the cancel function for a scan ID so the scan can
// be stopped later through the CancelScan RPC.
func registerActiveScan(scanID string, userID string, cancel context.CancelFunc) error {
	scan := &activeScan{
		userID: strings.TrimSpace(userID),
		cancel: cancel,
	}
	// Reject duplicate IDs so one active scan maps to one registry entry.
	if _, loaded := activeSubdomainMap.LoadOrStore(scanID, scan); loaded {
		return status.Error(codes.AlreadyExists, "scan_id is already in use")
	}
	return nil
}

// unregisterActiveScan removes a scan from the active registry after the run
// completes or fails so stale cancellations are not possible.
func unregisterActiveScan(scanID string) {
	activeSubdomainMap.Delete(scanID)
}

// lookupActiveScan returns the currently tracked scan for a scan ID when it is
// still running.
func lookupActiveScan(scanID string) (*activeScan, bool) {
	value, ok := activeSubdomainMap.Load(scanID)
	// Missing key means scan is not currently active.
	if !ok {
		return nil, false
	}

	scan, ok := value.(*activeScan)
	return scan, ok
}

// normalizeScanID trims user input so ID comparisons and storage are
// consistent across RPC calls.
func normalizeScanID(raw string) string {
	return strings.TrimSpace(raw)
}

// isCanceledError reports whether the error path should be treated as a scan
// cancellation, including both explicit context cancellation and deadline exit.
func isCanceledError(ctx context.Context, err error) bool {
	// With no explicit error, rely on context cancellation state.
	if err == nil {
		return ctx.Err() != nil
	}

	// Treat canceled/deadline failures as expected cancellation paths.
	return ctx.Err() != nil ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded)
}

// canceledScanError converts a canceled run into the canonical gRPC error
// returned by this service.
func canceledScanError() error {
	return status.Error(codes.Canceled, "scan canceled")
}
