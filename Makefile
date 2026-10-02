MODULE = $(shell go list -m)
PACKAGES = $(shell go list ./... | grep -v '/vendor/')

# Keep this version in sync with the generated .pb.go files.
PROTOC_GEN_GO_VERSION = v1.30.0

all: protob test

########################################
### Protocol Buffers

check_protoc_gen_go:
	@have=$$(protoc-gen-go --version 2>/dev/null | awk '{print $$2}'); \
	if [ "$$have" != "$(PROTOC_GEN_GO_VERSION)" ]; then \
		echo "protoc-gen-go $(PROTOC_GEN_GO_VERSION) is required; found $${have:-none}."; \
		echo "Install it with: go install google.golang.org/protobuf/cmd/protoc-gen-go@$(PROTOC_GEN_GO_VERSION)"; \
		echo "When upgrading, update PROTOC_GEN_GO_VERSION with the regenerated files."; \
		exit 1; \
	fi

protob: check_protoc_gen_go
	@echo "--> Building Protocol Buffers"
	@for protocol in message signature ecdsa-keygen ecdsa-signing; do \
		echo "Generating $$protocol.pb.go" ; \
		protoc --go_out=. ./protob/$$protocol.proto ; \
	done

build: protob
	go fmt ./...

########################################
### Testing

test_unit:
	@echo "--> Running Unit Tests"
	@echo "!!! WARNING: This will take a long time :)"
	go test -timeout 60m $(PACKAGES)

test_unit_race:
	@echo "--> Running Unit Tests (with Race Detection)"
	@echo "!!! WARNING: This will take a long time :)"
	go test -timeout 60m -race $(PACKAGES)

test:
	make test_unit

########################################
### Pre Commit

pre_commit: build test

########################################

# To avoid unintended conflicts with file names, always add to .PHONY
# # unless there is a reason not to.
# # https://www.gnu.org/software/make/manual/html_node/Phony-Targets.html
.PHONY: check_protoc_gen_go protob build test_unit test_unit_race test
