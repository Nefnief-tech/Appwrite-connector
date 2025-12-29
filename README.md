# Appwrite Connector

This is a Rust-based connector/adapter that accepts requests (mimicking Appwrite or as a backend service), encrypts the data using AES-256-GCM, and distributes it to Redis (cache) and Postgres (persistent storage).

## Features

- **Encryption**: All data is encrypted before storage using AES-256-GCM. The database only sees encrypted content.
- **Dual Storage**: Stores data in Postgres for durability and Redis for fast access.
- **Read-Through Cache**: On retrieval, checks Redis first. If missing, checks Postgres and backfills Redis.

## Prerequisites

- Rust (latest stable)
- PostgreSQL
- Redis

## Configuration

Copy `.env.example` to `.env` and configure your credentials:

```bash
cp .env.example .env
```

Ensure `ENCRYPTION_KEY` is a 32-byte hex string.

## Running

```bash
cargo run
```

## API

### Store Data (POST /data)

**Request:**
```json
{
  "some": "data",
  "nested": { "obj": 123 }
}
```

**Response:**
```json
{
  "id": "uuid-string",
  "status": "stored"
}
```

### Get Data (GET /data/:id)

**Response:**
```json
{
  "some": "data",
  "nested": { "obj": 123 }
}
```
