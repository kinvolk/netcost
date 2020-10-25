SHELL=/bin/bash -o pipefail

all: netcost

netcost: netcost.go pkg/netcostdata/netcost-assets-bpf.go
	go build -o netcost netcost.go

pkg/netcostdata/netcost-assets-bpf.go: bpf/netcost-bpf.c bpf/bpf_legacy.h
	clang -target bpf -O2 -g -c -x c bpf/netcost-bpf.c -o bpf/netcost-bpf.o
	go-bindata -pkg netcostdata -prefix bpf -modtime 1 -o pkg/netcostdata/netcost-assets-bpf.go \
		bpf/netcost-bpf.o
	rm -f bpf/netcost-bpf.o

clean:
	rm -f netcost pkg/netcostdata/netcost-assets-bpf.go

