package main

import (
	"go-server/internal/database"
	"log"
	"net"

	scan_port "go-server/gen/scan_port"
	scan_subdomain "go-server/gen/scan_subdomain"
	scanner "go-server/gen/scanner"
	users "go-server/gen/user"
	scanner_service "go-server/internal/service"
	user_service "go-server/internal/service"
	scan_port_service "go-server/internal/service/scan_port"
	scan_subdomain_service "go-server/internal/service/scan_subdomain"

	"google.golang.org/grpc"
)

func main() {
	if _, err := database.ConnectAndMigrate(); err != nil {
		log.Fatalf("failed to initialize database: %v", err)
	}

	// 1. Create a TCP listener on port 50051
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	// 2. Create a new gRPC server instance
	grpcServer := grpc.NewServer()

	// 3. Register our service implementation
	users.RegisterUserServiceServer(grpcServer, scanner_service.NewUserServer())
	scanner.RegisterScanServiceServer(grpcServer, user_service.NewScanServer())
	scan_subdomain.RegisterSubdomainScannerServiceServer(grpcServer, scan_subdomain_service.NewScanSubdomainServer())
	scan_port.RegisterScanPortServiceServer(grpcServer, scan_port_service.NewScanPortServer())

	log.Printf("server listening at %v", lis.Addr())

	// 4. Start serving requests
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}

}
