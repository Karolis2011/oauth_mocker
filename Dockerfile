# syntax=docker/dockerfile:1
# Use the official Rust image as the base image for building
FROM rust:1.86-alpine AS builder

# Set the working directory
WORKDIR /app

# Install necessary build dependencies
RUN apk add --no-cache musl-dev gcc

RUN --mount=type=bind,source=src,target=src \
    --mount=type=bind,source=templates,target=templates \
    --mount=type=bind,source=Cargo.toml,target=Cargo.toml \
    --mount=type=bind,source=Cargo.lock,target=Cargo.lock \
    --mount=type=cache,target=/app/target/ \
    --mount=type=cache,target=/usr/local/cargo/registry/ \
    cargo build --locked --release && cp target/release/oauth_mocker /app/oauth_mocker

# Use a minimal base image for the runtime
FROM scratch as server

# Set the working directory
WORKDIR /app

# Copy the compiled binary from the builder stage
COPY --from=builder /app/oauth_mocker /app/oauth_mocker

# Expose the port the application will run on
## ensure the container listens globally on port 8080
ENV ROCKET_ADDRESS=0.0.0.0
ENV ROCKET_PORT=8080

EXPOSE 8080

# Run the application
CMD ["./oauth_mocker"]
