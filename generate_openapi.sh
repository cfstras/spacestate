#!/bin/bash
set -euo pipefail

IMAGE=openapitools/openapi-generator-cli

# does not use experimental, but openssl build fails
#IMAGE=openapitools/openapi-generator-cli:v4.3.1

docker run --rm \
  -v ${PWD}:/local \
  -w /local \
  $IMAGE \
  generate \
  -i openapi.yml \
  -g rust-server \
  -o openapi/

cd openapi


echo "are you on nightly?"
echo "call:  rustup update nightly"

# necessary?
#export OPENSSL_ROOT_DIR="$(brew --prefix openssl)"
#export OPENSSL_INCLUDE_DIR="$OPENSSL_ROOT_DIR/include/"
#export OPENSSL_LIB_DIR="$OPENSSL_ROOT_DIR/lib/"
#export C_INCLUDE_PATH="$OPENSSL_ROOT_DIR/include/"
#export DEP_OPENSSL_INCLUDE="$OPENSSL_ROOT_DIR/include"

#cargo upgrade openssl
cargo run --example server # --features=openssl/vendored
