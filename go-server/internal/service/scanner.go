package service

import (
    "context"
    "log"
    
    // 1. GOTO: gen/scanner/scan_grpc.pb.go
    // Look for 'type ScanServiceServer interface'. This code must implement 
    // every method defined there to satisfy the gRPC server requirements.
    scanner "go-server/gen/scanner"
)

// scanServer implements the ScanServiceServer interface.
type scanServer struct {
    // 2. GOTO: gen/scanner/scan_grpc.pb.go
    // We embed UnimplementedScanServiceServer. This provides "forward compatibility."
    // If you add a new RPC to your proto but don't implement it here yet, 
    // the server will return a 'Unimplemented' error instead of crashing.
    scanner.UnimplementedScanServiceServer
}

// newScanServer is a constructor. Use this in your main.go to 
// register the service: scanner.RegisterScanServiceServer(grpcServer, newScanServer())
func NewScanServer() scanner.ScanServiceServer {
    return &scanServer{}
}

// RunTool maps directly to the 'rpc RunTool' defined in your proto file.
// - ctx: Used for cancellation (e.g., if the FastAPI client disconnects).
// - req: GOTO gen/scanner/scan.pb.go to see the 'ScanRequest' struct fields.
func (s *scanServer) RunTool(ctx context.Context, req *scanner.ScanRequest) (*scanner.ScanResponse, error) {
    
    // Accessing req.Target works because it was defined as 'string target = 1' in proto.
    log.Printf("Received scan request using %s for target: %s\n", req.ToolName, req.Target)

    // 3. GOTO: gen/scanner/scan.pb.go
    // Look for 'type ScanResponse struct'. We initialize it here to send data back.
    return &scanner.ScanResponse{
        ResultSummary: "Received scan request using " + req.ToolName + " for target: " + req.Target,
        Success:       true,
    }, nil
}
