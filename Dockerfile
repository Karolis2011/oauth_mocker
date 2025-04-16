# Use the official Rust image as the base image for building
FROM rust:1.86-alpine AS builder

# Set the working directory
WORKDIR /app

# Install necessary build dependencies
RUN apk add --no-cache musl-dev gcc

# Copy the project files into the container
COPY . .

# Build the project in release mode
RUN cargo build --release

# Use a minimal base image for the runtime
FROM scratch as server

# Set the working directory
WORKDIR /app

# Copy the compiled binary from the builder stage
COPY --from=builder /app/target/release/oauth_mocker /app/oauth_mocker

# Expose the port the application will run on
## ensure the container listens globally on port 8080
ENV ROCKET_ADDRESS=0.0.0.0
ENV ROCKET_PORT=8080

EXPOSE 8080

# Run the application
CMD ["./oauth_mocker"]
