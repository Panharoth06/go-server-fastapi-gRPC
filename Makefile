# Variables
PROTO_DIR = proto
GO_OUT = go-server/gen
PY_OUT = fastapi-gateway/app/gen
SQLC_CONFIG = go-server/sqlc.yaml
UV_CACHE_DIR ?= /tmp/uv-cache
GOBIN := $(shell go env GOPATH 2>/dev/null)/bin
export PATH := $(PATH):$(GOBIN)

.PHONY: proto-go proto-py proto sqlc clean check-protoc check-go-plugins check-uv

# Generate both
proto: proto-go proto-py

# Generate sqlc queries
sqlc:
	cd go-server && go run github.com/sqlc-dev/sqlc/cmd/sqlc@v1.27.0 generate -f $(notdir $(SQLC_CONFIG))

check-protoc:
	@command -v protoc >/dev/null || ( \
		echo "error: protoc is not installed"; \
		echo "install: sudo apt install protobuf-compiler"; \
		exit 1 )

check-go-plugins:
	@command -v protoc-gen-go >/dev/null || ( \
		echo "error: protoc-gen-go is not in PATH"; \
		echo "install: go install google.golang.org/protobuf/cmd/protoc-gen-go@latest"; \
		echo "then add ~/go/bin to PATH"; \
		exit 1 )
	@command -v protoc-gen-go-grpc >/dev/null || ( \
		echo "error: protoc-gen-go-grpc is not in PATH"; \
		echo "install: go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest"; \
		echo "then add ~/go/bin to PATH"; \
		exit 1 )

check-uv:
	@command -v uv >/dev/null || ( \
		echo "error: uv is not installed"; \
		echo "install: https://docs.astral.sh/uv/getting-started/installation/"; \
		exit 1 )

# Generate Go code
proto-go: check-protoc check-go-plugins
	mkdir -p $(GO_OUT)
	find $(GO_OUT) -type f -name '*.pb.go' -delete
	protoc --proto_path=$(PROTO_DIR) \
		--go_out=go-server --go_opt=module=go-server \
		--go-grpc_out=go-server --go-grpc_opt=module=go-server \
		$(PROTO_DIR)/*.proto

# Generate Python code using uv
proto-py: check-protoc check-uv
	mkdir -p $(PY_OUT)
	touch $(PY_OUT)/__init__.py
	cd fastapi-gateway && UV_CACHE_DIR=$(UV_CACHE_DIR) uv run python -m grpc_tools.protoc -I../$(PROTO_DIR) \
		--python_out=app/gen \
		--grpc_python_out=app/gen \
		../$(PROTO_DIR)/*.proto
	find $(PY_OUT) -name '*_pb2_grpc.py' -type f -exec sed -i -E 's/^import ([a-zA-Z0-9_]+_pb2) as /from . import \1 as /' {} +

# Remove generated files
clean:
	rm -rf $(GO_OUT)/*
	rm -rf $(PY_OUT)/*
