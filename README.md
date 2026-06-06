# 🏦 Bank Ledger API

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Render](https://img.shields.io/badge/Deployed%20on-Render-46E3B7?style=flat&logo=render)](https://render.com)
[![API Docs](https://img.shields.io/badge/Swagger-Docs-85EA2D?style=flat&logo=swagger)](https://your-app.onrender.com/swagger/index.html)

A production-grade double-entry accounting ledger API built with Go, featuring JWT authentication, rate limiting, idempotency, and comprehensive monitoring.

## ✨ Features

- **Double-Entry Accounting** - Complete debit/credit tracking with transaction integrity
- **JWT Authentication** - Secure token-based authentication with configurable expiry
- **Idempotency Support** - Prevent duplicate transactions with idempotency keys
- **Rate Limiting** - Global and endpoint-specific rate limiting to prevent abuse
- **Database Connection Pooling** - Optimized PostgreSQL connection management
- **Structured Logging** - JSON formatted logs with request tracing
- **Prometheus Metrics** - Built-in metrics endpoint for monitoring
- **CORS Support** - Configurable cross-origin resource sharing
- **API Documentation** - Auto-generated Swagger/OpenAPI documentation

## 🚀 Quick Start

### Prerequisites

- Go 1.21 or higher
- PostgreSQL 13 or higher
- Make (optional, for using Makefile)

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/paularinzee/Go-Bank-Ledger.git
cd Go-Bank-Ledger
```
2. **Install dependencies**
```bash
go mod download
```
3. ***Set up environment variables**
```bash
cp .env.example .env
# Edit .env with your configuration
```
4. **Set up the database**
```bash
# Create database
createdb bank_ledger

# Run migrations (example - adjust to your migration tool)
psql -d bank_ledger -f migrations/001_initial_schema.sql
```
5. **Run the application**
```bash
# Development mode
go run main.go

# Or using make
make server
```
## 🛠️ API Endpoints

### Public Routes

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/register` | Create new user account |
| POST | `/login` | Authenticate and receive JWT |
| GET | `/health` | Health check with dependency status |
| GET | `/ready` | Readiness probe for orchestration |
| GET | `/metrics` | Prometheus metrics endpoint |
| GET | `/swagger/*` | API documentation |

### Protected Routes (Require JWT)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/accounts` | Create new bank account |
| GET | `/accounts` | List all user accounts |
| GET | `/accounts/{id}` | Get account details |
| POST | `/accounts/{id}/deposit` | Deposit funds |
| POST | `/accounts/{id}/withdraw` | Withdraw funds |
| POST | `/transfers` | Transfer between accounts |
| GET | `/accounts/{id}/entries` | Get account entries |
| GET | `/accounts/{id}/reconcile` | Reconcile account |
| GET | `/transactions/{id}` | Get transaction details |

### Example API Calls

#### Register User
```bash
curl -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securepassword",
    "name": "John Doe"
  }'
```
#### Login 
```bash
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securepassword"
  }'
```

### Create Account (Authenticated)
```bash
curl -X POST http://localhost:8080/accounts \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "account_name": "Checking Account",
    "currency": "USD",
    "initial_balance": 1000.00
  }'
```
### Deposit Funds
```bash
curl -X POST http://localhost:8080/accounts/1/deposit \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: unique-key-123" \
  -d '{
    "amount": 500.00,
    "description": "Salary deposit"
  }'
```
### Transfer Between Accounts
```bash
curl -X POST http://localhost:8080/transfers \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: transfer-456" \
  -d '{
    "from_account_id": 1,
    "to_account_id": 2,
    "amount": 250.00,
    "description": "Monthly transfer"
  }'
```

 