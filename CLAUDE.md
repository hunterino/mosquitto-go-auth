# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Mosquitto Go Auth is a CGo authentication/authorization plugin for the Eclipse Mosquitto MQTT broker. It bridges C (Mosquitto plugin API) and Go to provide pluggable auth backends. The project is archived but stable.

**Requirements**: Go 1.24+, CGO enabled, Mosquitto dev headers (`/usr/local/include/` or `/usr/include/`)

## Build Commands

```bash
make                    # Build go-auth.so plugin + pw password utility
make without-vcs        # Build without VCS info (CI/CD)
make clean              # Remove go-auth.so, go-auth.h, pw

# Tests (require backends running: PostgreSQL, Redis, MongoDB, MySQL)
make test               # All tests (backends + cache + hashing)
make test-backends      # Backend tests only (builds plugin/ first)
make test-cache         # Cache tests only
make test-hashing       # Hashing tests only

# Run a single test
go test ./backends -v -count=1 -run TestPostgresGetUser

# Docker-based testing (includes all backend services)
make build-docker-test  # Build test image from Dockerfile.runtest
make run-docker-test    # Run all tests in Docker

# Password hash generation
./pw -h pbkdf2 -a sha512 -i 100000 -s 16 -l 64 -p "mypassword"
./pw -h bcrypt -c 10 -p "mypassword"

# gRPC code generation
make service            # Regenerate from grpc/auth.proto
```

**macOS note**: The Makefile adds `-undefined dynamic_lookup` to LDFLAGS automatically on Darwin.

## Architecture

### CGo Bridge (`go-auth.go`)

The plugin exports four C functions that Mosquitto calls:

- `AuthPluginInit` - Called once at broker startup; parses config, initializes backends/cache/observability
- `AuthUnpwdCheck` - Called on every MQTT CONNECT; returns `AuthGranted(1)`, `AuthRejected(0)`, or `AuthError(2)`
- `AuthAclCheck` - Called on PUBLISH/SUBSCRIBE; same return values
- `AuthPluginCleanup` - Called on broker shutdown

Both auth checks support retry logic (`retry_count` option) and optional caching.

### Backend System (`backends/`)

All backends implement the `Backend` interface (`backends/backends.go`):

```go
type Backend interface {
    GetUser(username, password, clientid string) (bool, error)
    GetSuperuser(username string) (bool, error)
    CheckAcl(username, topic, clientId string, acc int32) (bool, error)
    GetName() string
    Halt()
}
```

12 backends: `postgres`, `mysql`, `sqlite`, `redis`, `mongo`, `jwt`, `http`, `grpc`, `ldap`, `files`, `js`, `plugin`

Backend config options use prefixes (e.g., `auth_opt_pg_host` for PostgreSQL, `auth_opt_mysql_host` for MySQL). The prefix mapping is in `allowedBackendsOptsPrefix`.

**Prefix routing**: When `check_prefix` is enabled, usernames like `pg_john` route to the PostgreSQL backend only. The `Backends` struct maintains separate checker lists for user, superuser, and ACL checks.

### Caching (`cache/`)

Two cache implementations behind the `Store` interface:
- **In-memory**: `ttlcache/v3` with configurable TTL and jitter
- **Redis**: Single instance or cluster mode

Cache keys are SHA1 hashes of `username:password` (auth) or `username:topic:clientid:acc` (ACL).

### Hashing (`hashing/`)

Three algorithms: PBKDF2 (default, SHA512), Bcrypt, Argon2ID. Per-backend hasher config is supported (e.g., `auth_opt_pg_hasher`).

### Observability (`observability/`)

OpenTelemetry metrics exported as Prometheus (port 9090 by default). Structured JSON logging. Health endpoint at `/health`. Enabled via `auth_opt_observability_enabled true`.

### Topic Matching (`backends/topics/`)

MQTT wildcard matching: `+` matches one level, `#` matches all remaining levels (must be last).

## Configuration

All plugin options are passed via `auth_opt_` prefix in `mosquitto.conf`. See `conf_example/conf.d/go-auth.conf` for a complete example. Key options:

- `auth_opt_backends` - Comma-separated list of backends to enable
- `auth_opt_cache` / `auth_opt_cache_type` - Enable caching (go/redis)
- `auth_opt_hasher` - Global password hashing algorithm
- `auth_opt_log_level` - debug/info/warn/error/fatal
- `auth_opt_observability_enabled` - Enable metrics/structured logging

## Testing

Backend tests require running database services. The easiest path is Docker:

```bash
make build-docker-test && make run-docker-test
```

For local testing, you need PostgreSQL, Redis, MongoDB, and MySQL running with test databases. The `run-test-in-docker.sh` script sets up the test environment. Test fixtures are in `test-files/`.

The `plugin/` directory contains a test plugin that must be built before running backend tests (`make test` handles this automatically).
