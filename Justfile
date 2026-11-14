# Copyright 2026 James Casey
# SPDX-License-Identifier: Apache-2.0

# Standard Beamtalk project targets.
# See: https://beamtalk.dev/docs/tooling

# Build the project
build:
    beamtalk build

# Run the test suite
test:
    beamtalk test --warnings-as-errors

# Check formatting
fmt:
    beamtalk fmt-check

# Format in place
fmt-fix:
    beamtalk fmt

# Lint source files. Depends on build so the native modules and native deps
# (oidcc, jose) are compiled and their FFI types are known to the checker.
lint: build
    beamtalk lint --warnings-as-errors

# Remove build artifacts
clean:
    rm -rf _build

# Full CI check (fmt + lint + build + test)
ci: fmt lint build test

# Tag a release from beamtalk.toml version
release:
    #!/usr/bin/env bash
    set -euo pipefail
    version=$(grep '^version' beamtalk.toml | head -1 | sed 's/.*= *"\(.*\)"/\1/')
    git tag "v${version}"
    echo "Tagged v${version}"

# Push release tags to origin
publish:
    git push origin --tags
