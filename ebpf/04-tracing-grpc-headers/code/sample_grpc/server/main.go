package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"

	pb "github.com/maheshrayas/grpc/pb/proto"

	"google.golang.org/grpc"
)

type HeaderField struct {
	Name, Value string
	Sensitive   bool
}

type MetaHeadersFrame struct {
	hdr       *int
	Fields    []HeaderField
	Truncated bool
}

type server struct {
	pb.UnimplementedGreeterServer
}

func (s *server) SayHello(ctx context.Context, req *pb.HelloRequest) (*pb.HelloReply, error) {
	return &pb.HelloReply{Message: "Hello, " + req.Name + "!"}, nil
}

func (s *server) SayGoodbye(ctx context.Context, req *pb.GoodbyeRequest) (*pb.GoodbyeReply, error) {
	return &pb.GoodbyeReply{Message: "Goodbye, " + req.Name + "!"}, nil
}

func main() {


	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	
	grpcServer := grpc.NewServer()
	pb.RegisterGreeterServer(grpcServer, &server{})
    fmt.Printf("PID: %d\n", os.Getpid())
	log.Println("gRPC server listening on :50051")
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
