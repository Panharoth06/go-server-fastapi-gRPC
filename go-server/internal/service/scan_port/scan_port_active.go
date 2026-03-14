package scanport

import (
	"context"
	"errors"
	"strings"
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// This file manages the in-memory registry of active port scans.
// It is responsible for tracking which scans are cancellable, guarding
// ownership checks, and normalizing scan lifecycle error handling.

type activeScan struct {
	userID     string
	cancel     context.CancelCauseFunc
	cancelOnce sync.Once
}

var activeScanPortMap sync.Map

// registerActiveScanPort stores the cancel function for a scan ID so the scan can
// be stopped later through the CancelScan RPC.
func registerActiveScanPort(scanID string, userID string, cancel context.CancelCauseFunc) error {
	scan := &activeScan{
		userID: strings.TrimSpace(userID),
		cancel: cancel,
	}

	if _, loaded := activeScanPortMap.LoadOrStore(scanID, scan); loaded {
		return status.Error(codes.AlreadyExists, "scan_id is already in use")
	}
	return nil
}

// unregisterActiveScanPort removes a scan from the active registry after the run
// completes or fails so stale cancellations are not possible.
func unregisterActiveScanPort(scanID string) {
	activeScanPortMap.Delete(scanID)
}

// lookupActiveScan returns the currently tracked scan for a scan ID when it is
// still running.
func lookupActiveScanPort(scanID string) (*activeScan, bool) {
	value, ok := activeScanPortMap.Load(scanID)

	if !ok {
		return nil, false
	}

	scan, ok := value.(*activeScan)
	return scan, ok
}

func isCanceledError(ctx context.Context, err error) bool {
	if err == nil {
		return ctx.Err() != nil
	}

	return ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func canceledScanError() error {
	return status.Error(codes.Canceled, "scan canceled")
}

func normalizeScanID(raw string) string {
	return strings.TrimSpace(raw)
}
