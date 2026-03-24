BINARY := pigeon-mesh
OUTDIR := build

.PHONY: build clean test vet

build:
	@mkdir -p $(OUTDIR)
	go build -o $(OUTDIR)/$(BINARY) ./cmd/pigeon-mesh

clean:
	rm -rf $(OUTDIR)

test:
	go test ./...

vet:
	go vet ./...

e2e: build
	sudo go test -tags=e2e -v -count=1 ./e2e