package service

import (
	"context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"log"

	scanner "go-server/gen/scanner"
)

// scanServer implements the ScanServiceServer interface.
type scanServer struct {
	// Embedding keeps forward compatibility for newly added RPC methods.
	scanner.UnimplementedScanServiceServer
}

// NewScanServer is a constructor. Use this in our main.go to
// register the service: scanner.RegisterScanServiceServer(grpcServer, NewScanServer())
func NewScanServer() scanner.ScanServiceServer {
	return &scanServer{}
}

// RunTool maps directly to the 'rpc RunTool' defined in your proto file.
// - ctx: Used for cancellation (e.g., if the FastAPI client disconnects).
// - req: GOTO gen/scanner/scan.pb.go to see the 'ScanRequest' struct fields.
func (s *scanServer) RunTool(ctx context.Context, req *scanner.ScanRequest) (*scanner.ScanResponse, error) {
	select {
	case <-ctx.Done():
		// Return a precise status code based on why the context ended.
		switch ctx.Err() {
		case context.Canceled:
			return nil, status.Error(codes.Canceled, "request canceled by client")
		case context.DeadlineExceeded:
			return nil, status.Error(codes.DeadlineExceeded, "request deadline exceeded")
		default:
			return nil, status.Error(codes.Canceled, "request canceled")
		}
	default:
	}

	// Log the incoming request for traceability.
	log.Printf("Received scan request using %s for target: %s\n", req.ToolName, req.Target)

	// Return a simple success response (placeholder behavior).
	return &scanner.ScanResponse{
		ResultSummary: "Received scan request using " + req.ToolName + " for target: " + req.Target,
		Success:       true,
	}, nil
}
