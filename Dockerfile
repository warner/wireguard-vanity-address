# Dockerfile to build wireguard-vanity-address
# from https://github.com/LukeMathWalker/cargo-chef

# Build with docker build -t wgvanity .
# Invoke with docker run wgvanity [ string ]

# syntax=docker/dockerfile:1

ARG TARGETPLATFORM
ARG BUILDPLATFORM

FROM --platform=$BUILDPLATFORM lukemathwalker/cargo-chef:latest-rust-1 AS chef
WORKDIR /app

FROM --platform=$BUILDPLATFORM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM --platform=$BUILDPLATFORM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
# Build dependencies - this is the caching Docker layer!
RUN cargo chef cook --release --recipe-path recipe.json
# Build application
COPY . .
RUN cargo build --release --bin wireguard-vanity-address

# We do not need the Rust toolchain to run the binary!
FROM --platform=$TARGETPLATFORM debian:bookworm-slim AS runtime
WORKDIR /app
COPY --from=builder /app/target/release/wireguard-vanity-address /usr/local/bin

ENTRYPOINT ["/usr/local/bin/wireguard-vanity-address"]
CMD ["Rich"] # default is "Rich"; supply your own string as a parameter
