FROM rust:1-slim-bullseye AS builder
RUN rustup toolchain install stable-x86_64-unknown-linux-gnu
RUN rustup default stable

RUN apt-get update && apt-get install -y libclang-dev

COPY . /sources
WORKDIR /sources
RUN cargo build --release
RUN chown nobody:nogroup /sources/target/release/bibin


FROM debian:bullseye-slim
COPY --from=builder /sources/target/release/bibin /opt/bibin

WORKDIR /etc/secrets

USER nobody
EXPOSE 8000
ENTRYPOINT ["/opt/bibin"]
