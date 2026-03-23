BINARY := pigeon-mesh
OUTDIR := build

.PHONY: build clean test vet

build:
	go build -o $(OUTDIR)/$(BINARY) ./cmd/pigeon-mesh

clean:
	rm -rf $(OUTDIR)

test:
	go test ./...

vet:
	go vet ./...
