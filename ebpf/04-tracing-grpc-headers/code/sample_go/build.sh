#go version go1.24.5 linux/amd64

go build -gcflags="all=-N -l" -o sample
./sample