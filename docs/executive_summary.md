# Message Broker Auth Plugin — Executive Summary

## Purpose

Mosquitto Go Auth is a production-grade authentication and authorization plugin for the Eclipse Mosquitto message broker. It bridges C (Mosquitto plugin API) and Go to provide flexible, pluggable authentication backends while maintaining high performance. The plugin enables PostgreSQL-backed user authentication, fine-grained topic-level access control, and optional caching for scalable deployments. FiveX uses this plugin to secure message bus access with database-driven credentials.

## Current State

- **Maturity:** Stable (archived upstream, maintained by FiveX)
- **Version:** Latest stable branch
- **Last Activity:** Active maintenance for FiveX deployments
- **Test Coverage:** Comprehensive backend, cache, and hashing tests; requires running database services
- **Lines of Code:** ~8,000 lines (Go + C bridge)

## Tech Stack

| Component | Technology | Version |
|-----------|-----------|---------|
| **Language** | Go (CGo for C bridge) | 1.24+ |
| **Message Broker** | Eclipse Mosquitto | Latest stable |
| **Build Tool** | Make (CGo) | Standard |
| **Primary Backend** | PostgreSQL | 12+ (FiveX standard) |
| **Optional Caching** | Redis | 5+ or in-memory |
| **Password Hashing** | PBKDF2, Bcrypt, Argon2ID | Native Go implementations |
| **Testing** | Go test suite | - |
| **Observability** | OpenTelemetry | Optional |
| **Metrics** | Prometheus | Port 9090 |

## Key Capabilities

- **12 Auth Backends** - PostgreSQL, MySQL, SQLite, Redis, MongoDB, JWT, HTTP, gRPC, LDAP, Files, JavaScript, Plugin
- **Dual-Mode Caching** - In-memory TTL cache or Redis Cluster for distributed deployments
- **Multiple Hash Algorithms** - PBKDF2/SHA512 (default), Bcrypt with configurable cost, Argon2ID with time/memory parameters
- **Prefix-Based Routing** - Route user authentication to specific backends based on username prefixes
- **MQTT Topic Matching** - Full wildcard support (`+` single level, `#` multi-level)
- **Superuser Check** - Bypass ACL checks for elevated users
- **Retry Logic** - Configurable retry_count option for transient failures
- **OpenTelemetry Integration** - Structured JSON logging and Prometheus metrics export
- **Health Endpoint** - `/health` endpoint for monitoring plugin status
- **Per-Backend Configuration** - Prefix-based options (e.g., `auth_opt_pg_host`, `auth_opt_mysql_host`)
- **Dynamic Backend Loading** - Enable/disable backends via configuration without recompilation

## Architecture Overview

**CGo Plugin Layer** (`go-auth.go`):
- Exports four C functions called by Mosquitto:
  - `AuthPluginInit` - Initialization at broker startup; parses config, sets up backends/cache/observability
  - `AuthUnpwdCheck` - Called on every MQTT CONNECT; validates username/password
  - `AuthAclCheck` - Called on PUBLISH/SUBSCRIBE; checks topic access for user
  - `AuthPluginCleanup` - Cleanup on broker shutdown
- Returns `AuthGranted(1)`, `AuthRejected(0)`, or `AuthError(2)` for each check
- Implements retry logic with exponential backoff

**Backend Interface** (`backends/backends.go`):
```go
type Backend interface {
    GetUser(username, password, clientid string) (bool, error)
    GetSuperuser(username string) (bool, error)
    CheckAcl(username, topic, clientId string, acc int32) (bool, error)
    GetName() string
    Halt()
}
```

**12 Backend Implementations:**
- **PostgreSQL** (FiveX primary) - Custom query templates for flexible schema mapping
- **MySQL/MariaDB** - Drop-in replacement with JDBC driver compatibility
- **SQLite** - File-based, zero-config authentication
- **Redis** - High-performance cache backend with cluster support
- **MongoDB** - Document-based authentication with flexible schema
- **JWT** - Token-based auth with configurable claims validation
- **HTTP** - Webhook-based auth for external systems
- **gRPC** - RPC-based auth for microservices
- **LDAP** - Active Directory/OpenLDAP integration
- **Files** - Static file-based auth (development/testing)
- **JavaScript** - Custom auth logic via embedded V8
- **Plugin** - Chain multiple backends with fallback logic

**Caching Layer** (`cache/`):
- **In-Memory Cache** - `ttlcache/v3` with configurable TTL and jitter
  - Reduces backend load for frequently accessed users
  - Per-worker memory footprint ~100MB typical
- **Redis Cache** - Cluster-aware Redis client
  - Shares cache across multiple broker instances
  - Configurable database (FiveX uses DB 4)
- Cache keys: SHA1 hash of `username:password` (auth) or `username:topic:clientid:acc` (ACL)
- Invalidation: Time-based expiration with optional jitter to prevent thundering herd

**Hashing Strategies** (`hashing/`):
- **PBKDF2** (default) - PBKDF2-HMAC-SHA512 with configurable iterations (100,000+)
- **Bcrypt** - Industry standard with configurable cost factor (10-12 typical)
- **Argon2ID** - Modern password hashing with memory/time parameters
- Per-backend hasher support (e.g., `auth_opt_pg_hasher`)

**Topic Matching** (`backends/topics/`):
- MQTT wildcard pattern support
- `+` matches exactly one level
- `#` matches all remaining levels (must be last)
- Topic ACL patterns with username/client-id substitution

## Integration Points

- **Mosquitto Broker** - Loaded as dynamic library (`.so` on Linux/macOS)
- **PostgreSQL** - Queries `fivex` database for user credentials and ACL rules
- **Redis** (optional) - Connection to Redis for distributed cache
- **OpenTelemetry Collector** (optional) - Export metrics and structured logs
- **Prometheus** (optional) - Scrape metrics from port 9090
- **LDAP/Active Directory** - Integration via backends/ldap.go for enterprise auth

## Dependencies

**Build Time:**
- Go 1.24+ (CGO_ENABLED=1 required)
- C compiler with support for dynamic symbols (`-undefined dynamic_lookup` on macOS)
- Mosquitto development headers (`mqtt_plugin.h`, `mosquittopp.h`)
- Make build system
- protoc (for gRPC code generation if enabled)

**Runtime:**
- PostgreSQL client library (libpq)
- OpenSSL for TLS in database connections (optional but recommended)
- Redis client library (optional)
- gRPC and protobuf libraries (for gRPC backend)

**Test Dependencies:**
- Running PostgreSQL instance with test database
- Redis instance (if testing Redis cache)
- MongoDB instance (if testing MongoDB backend)
- MySQL/MariaDB instance (if testing MySQL backend)

## Known Risks & Technical Debt

- **CGo Complexity** - Symbol resolution varies by OS; macOS requires special LDFLAGS, Linux may require rpath adjustments
- **Plugin Crashes** - CGo panics crash the entire broker; Go runtime errors don't propagate clearly
- **Symbol Resolution** - Using `-undefined dynamic_lookup` on macOS hides symbol errors until runtime
- **Single Broker Instance** - No built-in clustering; distributed deployments require Redis for shared cache
- **Test Infrastructure** - Backend tests require Docker with 4+ running services; CI/CD setup is complex
- **Performance Monitoring** - Limited built-in observability; OpenTelemetry is optional
- **Configuration Reloading** - Changes require broker restart; no hot-reload for auth backends
- **Static ACL Files** - Topic ACL configuration is file-based, not database-driven
- **Archived Project** - Upstream repository is archived; security patches must be applied manually
- **CGo Memory Leaks** - Long-lived Go allocations (Go 1.x runtime) should be monitored

## Roadmap Considerations

- Implement dynamic configuration reloading via MQTT command topics (no restart required)
- Add database-driven ACL support instead of static ACL files
- Build broker clustering with consensus-based leader election
- Migrate from CGo to pure Go broker implementation (avoid plugin complexity)
- Implement distributed tracing (Jaeger integration) for troubleshooting
- Add connection/bandwidth limiting per user or client
- Support OAuth2/OIDC providers via HTTP backend improvements
- Implement certificate pinning for secure backend connections
- Add rate limiting and DOS protection mechanisms
- Build admin CLI for user/ACL management without direct database access
- Support MQTT 5.0 protocol features (message properties, topic aliases)
- Implement user revocation/rotation without credential storage changes
- Add multi-tenancy support via topic namespace isolation
- Create plugin versioning and auto-update mechanism
