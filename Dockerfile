# Stage 1: Build
FROM rust:1.82-bookworm as builder

WORKDIR /usr/src/app
COPY . .

# Build the application
RUN cargo build --release

# Stage 2: Runtime
FROM debian:bookworm-slim

# Install required runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/app

# Copy the binary from the builder stage
COPY --from=builder /usr/src/app/target/release/appwrite-connector .

# Copy static assets and config templates
COPY --from=builder /usr/src/app/test_app.html .

# Initialize keys.json if it doesn't exist
RUN if [ ! -f keys.json ]; then echo "{}" > keys.json; fi

# Create storage directory for local provider
RUN mkdir -p storage

# Expose the application port
EXPOSE 8080

# Run the application
CMD ["./appwrite-connector"]
