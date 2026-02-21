package main

import (
	"go-server/internal/database"
	"log"
	"net"

	scan_subdomain "go-server/gen/scan_subdomain"
	scanner "go-server/gen/scanner"
	users "go-server/gen/user"
	"go-server/internal/service"

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
	users.RegisterUserServiceServer(grpcServer, service.NewUserServer())
	scanner.RegisterScanServiceServer(grpcServer, service.NewScanServer())
	scan_subdomain.RegisterSubdomainScannerServer(grpcServer, service.NewScanSubdomainServer())

	log.Printf("server listening at %v", lis.Addr())

	// 4. Start serving requests
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}

}
