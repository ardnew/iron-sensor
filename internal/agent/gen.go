package agent

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -cc clang sensor ../../bpf/sensor.c -- -I../../bpf/headers -Wno-address-of-packed-member
