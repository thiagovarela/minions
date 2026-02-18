#!/bin/bash
# Wrapper to use zig cc as linker for cross-compilation
ZIG=${ZIG:-~/.local/share/mise/installs/zig/0.15.2/zig}
exec "$ZIG" cc -target x86_64-linux-musl "$@"
