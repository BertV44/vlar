# VeeamLogAnonymizer — Development Makefile
# Usage: make <target>

.PHONY: build test lint fmt release clean install help

# Default target
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

build: ## Build debug binary
	cargo build

release: ## Build optimized release binary
	cargo build --release
	@echo "\nBinary: target/release/veeam-log-anonymizer"
	@ls -lh target/release/veeam-log-anonymizer 2>/dev/null || true

test: ## Run all tests (unit + integration)
	cargo test --verbose

test-unit: ## Run unit tests only
	cargo test --lib --verbose

test-integration: ## Run integration tests only
	cargo test --test integration_test --verbose

lint: ## Run clippy linter
	cargo clippy --all-targets -- -D warnings

fmt: ## Format code
	cargo fmt --all

fmt-check: ## Check formatting without changes
	cargo fmt --all -- --check

check: fmt-check lint test ## Run all checks (CI equivalent)

clean: ## Clean build artifacts
	cargo clean

install: ## Install binary to ~/.cargo/bin
	cargo install --path .

# Cross-compilation targets (requires cross: cargo install cross)
build-linux: ## Build for Linux x86_64 (static, musl)
	cross build --release --target x86_64-unknown-linux-musl

build-linux-arm: ## Build for Linux ARM64
	cross build --release --target aarch64-unknown-linux-musl

build-windows: ## Build for Windows x86_64
	cross build --release --target x86_64-pc-windows-gnu

build-all: build-linux build-linux-arm build-windows release ## Build for all platforms
	@echo "\nAll builds complete:"
	@ls -lh target/x86_64-unknown-linux-musl/release/veeam-log-anonymizer 2>/dev/null || true
	@ls -lh target/aarch64-unknown-linux-musl/release/veeam-log-anonymizer 2>/dev/null || true
	@ls -lh target/x86_64-pc-windows-gnu/release/veeam-log-anonymizer.exe 2>/dev/null || true
	@ls -lh target/release/veeam-log-anonymizer 2>/dev/null || true

# Quick test with sample data
demo: release ## Run a quick demo with sample log
	@mkdir -p /tmp/vla-demo-input /tmp/vla-demo-output
	@echo '[2025-01-01 10:00:00] admin@company.com connected from 192.168.1.100' > /tmp/vla-demo-input/test.log
	@echo '[2025-01-01 10:00:01] CORP\john.doe authenticated' >> /tmp/vla-demo-input/test.log
	@echo '[2025-01-01 10:00:02] DNS: mail.company.com -> 10.0.0.50' >> /tmp/vla-demo-input/test.log
	@echo '[2025-01-01 10:00:03] VMware vSphere 8.0.3.0 - localhost: 127.0.0.1' >> /tmp/vla-demo-input/test.log
	./target/release/veeam-log-anonymizer -d /tmp/vla-demo-input -o /tmp/vla-demo-output -f -D -m -s
	@echo "\n=== Original ==="
	@cat /tmp/vla-demo-input/test.log
	@echo "\n=== Anonymized ==="
	@cat /tmp/vla-demo-output/test.log
	@rm -rf /tmp/vla-demo-input /tmp/vla-demo-output
