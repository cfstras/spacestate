FROM rust:1-slim-buster as builder

WORKDIR /usr/src/spacestate

RUN apt-get update && apt-get install --no-install-recommends -y \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.* ./
# Dummy main file to fetch & build dependencies
RUN --mount=type=cache,target=/usr/src/spacestate/target \
    mkdir src \
    && echo "fn main() {}" > src/main.rs \
    && cargo build --release \
    && rm -rf src

COPY build.rs ./
COPY src/ src/

# Build the real app (touch main file because cargo would ignore it otherwise)
RUN --mount=type=cache,target=/usr/src/spacestate/target \
    touch src/main.rs && cargo install --path .

FROM debian:buster-slim
#RUN apt-get update && apt-get install -y extra-runtime-dependencies && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/cargo/bin/spacestate /usr/local/bin/spacestate

ENV ROCKET_ADDRESS 0.0.0.0
ENV ROCKET_PORT 8000
CMD ["spacestate", "mumble.flipdot.org"]
