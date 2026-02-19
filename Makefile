# Minions build and release automation
# Cross-compiles from macOS (aarch64-apple-darwin) to Linux (x86_64-unknown-linux-musl)
#
# Prerequisites:
#   brew install FiloSottile/musl-cross/musl-cross
#   rustup target add x86_64-unknown-linux-musl
#
# Usage:
#   make build                    # Build all binaries for Linux
#   make release                  # Build + create tarball
#   make publish VERSION=v0.1.0   # Build + create GitHub release

TARGET = x86_64-unknown-linux-musl
RELEASE_DIR = target/$(TARGET)/release
VERSION ?= $(shell git describe --tags --always)
TARBALL = minions-$(VERSION)-$(TARGET).tar.gz
BINARIES = minions minions-agent minions-node minions-vsock-cli

.PHONY: all build release publish clean check-musl-cross check-version

all: build

# Check if musl-cross is installed
check-musl-cross:
	@which x86_64-linux-musl-gcc > /dev/null || \
		(echo "Error: x86_64-linux-musl-gcc not found. Install musl-cross:" && \
		 echo "  brew install FiloSottile/musl-cross/musl-cross" && \
		 exit 1)

# Build all binaries for Linux
build: check-musl-cross
	@echo "Building for $(TARGET)..."
	cargo build --release --target $(TARGET) \
		-p minions \
		-p minions-agent \
		-p minions-node \
		-p minions-vsock-cli
	@echo "✓ Build complete. Binaries in $(RELEASE_DIR)/"
	@ls -lh $(RELEASE_DIR)/minions*

# Create a release tarball
release: build
	@echo "Creating release tarball $(TARBALL)..."
	@mkdir -p dist
	@rm -f dist/$(TARBALL)
	@tar -czf dist/$(TARBALL) -C $(RELEASE_DIR) $(BINARIES)
	@echo "✓ Tarball created: dist/$(TARBALL)"
	@ls -lh dist/$(TARBALL)
	@echo ""
	@echo "Contents:"
	@tar -tzf dist/$(TARBALL)

# Check that VERSION is set for publish
check-version:
	@if [ -z "$(VERSION)" ] || [ "$(VERSION)" = "" ]; then \
		echo "Error: VERSION not set. Usage: make publish VERSION=v0.1.0"; \
		exit 1; \
	fi

# Create a GitHub release with binaries
publish: check-version release
	@echo "Publishing GitHub release $(VERSION)..."
	@if git rev-parse "$(VERSION)" >/dev/null 2>&1; then \
		echo "Tag $(VERSION) already exists. Skipping tag creation."; \
	else \
		echo "Creating tag $(VERSION)..."; \
		git tag -a "$(VERSION)" -m "Release $(VERSION)"; \
		git push origin "$(VERSION)"; \
	fi
	@echo "Creating GitHub release..."
	gh release create "$(VERSION)" \
		dist/$(TARBALL) \
		--title "Release $(VERSION)" \
		--notes "Automated release for $(VERSION). See CHANGELOG for details." \
		--draft=false
	@echo "✓ Release published: https://github.com/thiagovarela/minions/releases/tag/$(VERSION)"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	cargo clean
	rm -rf dist/
	@echo "✓ Clean complete"
