BINARY := pigeon-mesh
OUTDIR := build

.PHONY: build clean test vet fmt e2e perf

build:
	@mkdir -p $(OUTDIR)
	go build -o $(OUTDIR)/$(BINARY) ./cmd/pigeon-mesh

clean:
	rm -rf $(OUTDIR)

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w cmd internal e2e perf

e2e: build
	sudo go test -tags=e2e -v -count=1 ./e2e

perf: build
	sudo go test -tags=perf -v -count=1 -timeout=3600s ./perf
