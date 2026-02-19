package main

import (
	"log"
	"net"

	"go-server/internal/service"

	"google.golang.org/grpc"

	users "go-server/gen/user"
	scanner "go-server/gen/scanner"
)

func main() {
	// 1. Create a TCP listener on port 50051
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	// 2. Create a new gRPC server instance
	grpcServer := grpc.NewServer()


	grpcServer = grpc.NewServer()
	
	// 3. Register our service implementation
	users.RegisterUserServiceServer(grpcServer, service.NewUserServer())
	scanner.RegisterScanServiceServer(grpcServer, service.NewScanServer())
	

	log.Printf("server listening at %v", lis.Addr())

	// 4. Start serving requests
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}


}
