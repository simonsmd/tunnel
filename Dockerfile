FROM lukemathwalker/cargo-chef:latest-rust-1.89.0 AS chef
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare  --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim AS runtime
WORKDIR app
RUN apt-get update
RUN apt-get install -y openssl
COPY --from=builder /app/target/release/tunnel /usr/local/bin
ENTRYPOINT ["/usr/local/bin/tunnel"]
