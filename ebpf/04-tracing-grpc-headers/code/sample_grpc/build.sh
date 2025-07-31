 go mod tidy
 go build -gcflags="all=-N -l"  -o grpc ./server/main.go
 ./grpc

