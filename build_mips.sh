#!/bin/sh
set -eux
command -v cross || cargo install cross

export TARGET=mips-unknown-linux-musl

export RUSTFLAGS="-C target-feature=+crt-static"
cross build --target $TARGET --release
