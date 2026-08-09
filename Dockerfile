# Build
FROM rust:1.90-slim AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --bin transit

# Run. Distroless-style: no shell, no package manager, nothing to pivot to.
# An enforcement point with a shell in it is a worse hole than the one it
# closes.
FROM gcr.io/distroless/cc-debian12
COPY --from=build /src/target/release/transit /usr/local/bin/transit
COPY examples/guard.toml /etc/transit/guard.toml
EXPOSE 8080
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/transit"]
CMD ["guard", "--config", "/etc/transit/guard.toml"]
