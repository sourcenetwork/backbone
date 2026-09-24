# Rust DefraDB image for the soak (M2). Same as defradb.rs/Dockerfile at 8d8bb299f plus
# libdbus-1-dev / libdbus-1-3, which the keyring crate's libdbus-sys needs on Linux and the
# upstream file omits (build fails at libdbus-sys v0.2.7). Build with the defradb.rs checkout
# as the context: docker build -f crates/soak/docker/defra.Dockerfile -t soak-defra:<rev> <defradb.rs>
FROM rust:1.93-bookworm AS builder
WORKDIR /build
COPY . .
RUN apt-get update && apt-get install -y libssl-dev pkg-config protobuf-compiler libdbus-1-dev
RUN cargo build --release -p cli

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates libssl3 libdbus-1-3 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/defra /usr/local/bin/defra
EXPOSE 9161 9171 9181
ENTRYPOINT ["defra"]
