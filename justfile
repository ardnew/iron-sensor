# Build the iron-sensor binary.
build: generate
    CGO_ENABLED=0 go build -o bin/iron-sensor ./cmd/iron-sensor/

# Run go vet on all packages.
vet: generate
    go vet ./...

# Run all tests.
test: generate
    go test ./...

# Compile BPF programs and generate Go bindings (requires clang + libbpf-dev).
generate:
    go generate ./internal/agent/

# Regenerate vmlinux.h from the running kernel's BTF (requires bpftool).
vmlinux:
    echo "/* Generated from kernel $(uname -r) on $(date -u +%Y-%m-%d) */" > bpf/headers/vmlinux.h
    bpftool btf dump file /sys/kernel/btf/vmlinux format c >> bpf/headers/vmlinux.h

# Build with BPF generation.
build-full: generate build

# Run in dev mode with stdout sink.
run-dev: build
    sudo ./bin/iron-sensor --config config.dev.yaml

# Run end-to-end tests (requires root and BPF support).
test-e2e: build
    go test -tags e2e -v -count=1 ./test/e2e/

# Remove build artifacts.
clean:
    rm -rf bin/
    rm -f internal/agent/sensor_x86_bpfel.o
