package observability

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

var (
	// Global metrics instance
	metrics *Metrics
	once    sync.Once
)

// Metrics holds all the metric instruments
type Metrics struct {
	meter metric.Meter

	// Authentication metrics
	authAttempts        metric.Int64Counter
	authSuccess         metric.Int64Counter
	authFailure         metric.Int64Counter
	authLatency         metric.Float64Histogram

	// ACL metrics
	aclChecks           metric.Int64Counter
	aclGranted          metric.Int64Counter
	aclDenied           metric.Int64Counter
	aclLatency          metric.Float64Histogram

	// Superuser metrics
	superuserChecks     metric.Int64Counter
	superuserGranted    metric.Int64Counter

	// Backend metrics
	backendCalls        metric.Int64Counter
	backendErrors       metric.Int64Counter
	backendLatency      metric.Float64Histogram

	// Cache metrics
	cacheHits           metric.Int64Counter
	cacheMisses         metric.Int64Counter

	// Connection pool metrics (for PostgreSQL)
	poolConnections     metric.Int64UpDownCounter
	poolIdleConnections metric.Int64UpDownCounter
	poolWaitTime        metric.Float64Histogram

	// Health check
	healthCheckStatus   metric.Int64Gauge
}

// Initialize sets up the metrics system
func Initialize(ctx context.Context, serviceName string, metricsPort int) error {
	var err error
	once.Do(func() {
		// Create Prometheus exporter
		exporter, exporterErr := prometheus.New()
		if exporterErr != nil {
			err = fmt.Errorf("failed to create Prometheus exporter: %w", exporterErr)
			return
		}

		// Create meter provider with the exporter
		provider := sdkmetric.NewMeterProvider(
			sdkmetric.WithReader(exporter),
		)

		// Set as global provider
		otel.SetMeterProvider(provider)

		// Create meter
		meter := provider.Meter(
			serviceName,
			metric.WithInstrumentationVersion("1.0.0"),
		)

		// Initialize metrics struct
		metrics = &Metrics{meter: meter}

		// Initialize all metrics
		if initErr := metrics.initMetrics(); initErr != nil {
			err = fmt.Errorf("failed to initialize metrics: %w", initErr)
			return
		}

		// Start Prometheus HTTP server if port is specified
		if metricsPort > 0 {
			go func() {
				mux := http.NewServeMux()
				mux.Handle("/metrics", promhttp.Handler())
				mux.HandleFunc("/health", healthCheckHandler)

				addr := fmt.Sprintf(":%d", metricsPort)
				log.Infof("Starting metrics server on %s", addr)

				if serverErr := http.ListenAndServe(addr, mux); serverErr != nil {
					log.Errorf("Failed to start metrics server: %v", serverErr)
				}
			}()
		}

		log.Info("Observability initialized successfully")
	})

	return err
}

// initMetrics initializes all metric instruments
func (m *Metrics) initMetrics() error {
	var err error

	// Authentication metrics
	m.authAttempts, err = m.meter.Int64Counter(
		"mosquitto_auth_attempts_total",
		metric.WithDescription("Total number of authentication attempts"),
	)
	if err != nil {
		return err
	}

	m.authSuccess, err = m.meter.Int64Counter(
		"mosquitto_auth_success_total",
		metric.WithDescription("Total number of successful authentications"),
	)
	if err != nil {
		return err
	}

	m.authFailure, err = m.meter.Int64Counter(
		"mosquitto_auth_failure_total",
		metric.WithDescription("Total number of failed authentications"),
	)
	if err != nil {
		return err
	}

	m.authLatency, err = m.meter.Float64Histogram(
		"mosquitto_auth_latency_ms",
		metric.WithDescription("Authentication latency in milliseconds"),
		metric.WithUnit("ms"),
	)
	if err != nil {
		return err
	}

	// ACL metrics
	m.aclChecks, err = m.meter.Int64Counter(
		"mosquitto_acl_checks_total",
		metric.WithDescription("Total number of ACL checks"),
	)
	if err != nil {
		return err
	}

	m.aclGranted, err = m.meter.Int64Counter(
		"mosquitto_acl_granted_total",
		metric.WithDescription("Total number of granted ACL checks"),
	)
	if err != nil {
		return err
	}

	m.aclDenied, err = m.meter.Int64Counter(
		"mosquitto_acl_denied_total",
		metric.WithDescription("Total number of denied ACL checks"),
	)
	if err != nil {
		return err
	}

	m.aclLatency, err = m.meter.Float64Histogram(
		"mosquitto_acl_latency_ms",
		metric.WithDescription("ACL check latency in milliseconds"),
		metric.WithUnit("ms"),
	)
	if err != nil {
		return err
	}

	// Superuser metrics
	m.superuserChecks, err = m.meter.Int64Counter(
		"mosquitto_superuser_checks_total",
		metric.WithDescription("Total number of superuser checks"),
	)
	if err != nil {
		return err
	}

	m.superuserGranted, err = m.meter.Int64Counter(
		"mosquitto_superuser_granted_total",
		metric.WithDescription("Total number of granted superuser privileges"),
	)
	if err != nil {
		return err
	}

	// Backend metrics
	m.backendCalls, err = m.meter.Int64Counter(
		"mosquitto_backend_calls_total",
		metric.WithDescription("Total number of backend calls"),
	)
	if err != nil {
		return err
	}

	m.backendErrors, err = m.meter.Int64Counter(
		"mosquitto_backend_errors_total",
		metric.WithDescription("Total number of backend errors"),
	)
	if err != nil {
		return err
	}

	m.backendLatency, err = m.meter.Float64Histogram(
		"mosquitto_backend_latency_ms",
		metric.WithDescription("Backend call latency in milliseconds"),
		metric.WithUnit("ms"),
	)
	if err != nil {
		return err
	}

	// Cache metrics
	m.cacheHits, err = m.meter.Int64Counter(
		"mosquitto_cache_hits_total",
		metric.WithDescription("Total number of cache hits"),
	)
	if err != nil {
		return err
	}

	m.cacheMisses, err = m.meter.Int64Counter(
		"mosquitto_cache_misses_total",
		metric.WithDescription("Total number of cache misses"),
	)
	if err != nil {
		return err
	}

	// Connection pool metrics
	m.poolConnections, err = m.meter.Int64UpDownCounter(
		"mosquitto_pool_connections",
		metric.WithDescription("Number of connections in the pool"),
	)
	if err != nil {
		return err
	}

	m.poolIdleConnections, err = m.meter.Int64UpDownCounter(
		"mosquitto_pool_idle_connections",
		metric.WithDescription("Number of idle connections in the pool"),
	)
	if err != nil {
		return err
	}

	m.poolWaitTime, err = m.meter.Float64Histogram(
		"mosquitto_pool_wait_time_ms",
		metric.WithDescription("Time waiting for a connection from the pool"),
		metric.WithUnit("ms"),
	)
	if err != nil {
		return err
	}

	// Health check
	m.healthCheckStatus, err = m.meter.Int64Gauge(
		"mosquitto_health_status",
		metric.WithDescription("Health check status (1=healthy, 0=unhealthy)"),
	)
	if err != nil {
		return err
	}

	// Set initial health status
	m.healthCheckStatus.Record(context.Background(), 1)

	return nil
}

// RecordAuthAttempt records an authentication attempt
func RecordAuthAttempt(ctx context.Context, backend string) {
	if metrics == nil {
		return
	}
	attrs := []attribute.KeyValue{
		attribute.String("backend", backend),
	}
	metrics.authAttempts.Add(ctx, 1, metric.WithAttributes(attrs...))
}

// RecordAuthSuccess records a successful authentication
func RecordAuthSuccess(ctx context.Context, backend string, latencyMs float64) {
	if metrics == nil {
		return
	}
	attrs := []attribute.KeyValue{
		attribute.String("backend", backend),
	}
	metrics.authSuccess.Add(ctx, 1, metric.WithAttributes(attrs...))
	metrics.authLatency.Record(ctx, latencyMs, metric.WithAttributes(attrs...))
}

// RecordAuthFailure records a failed authentication
func RecordAuthFailure(ctx context.Context, backend string, reason string, latencyMs float64) {
	if metrics == nil {
		return
	}
	attrs := []attribute.KeyValue{
		attribute.String("backend", backend),
		attribute.String("reason", reason),
	}
	metrics.authFailure.Add(ctx, 1, metric.WithAttributes(attrs...))
	metrics.authLatency.Record(ctx, latencyMs, metric.WithAttributes(attrs...))
}

// RecordACLCheck records an ACL check
func RecordACLCheck(ctx context.Context, backend string, topic string, access string) {
	if metrics == nil {
		return
	}
	attrs := []attribute.KeyValue{
		attribute.String("backend", backend),
		attribute.String("access", access),
	}
	metrics.aclChecks.Add(ctx, 1, metric.WithAttributes(attrs...))
}

// RecordACLGranted records a granted ACL check
func RecordACLGranted(ctx context.Context, backend string, topic string, access string, latencyMs float64) {
	if metrics == nil {
		return
	}
	attrs := []attribute.KeyValue{
		attribute.String("backend", backend),
		attribute.String("access", access),
	}
	metrics.aclGranted.Add(ctx, 1, metric.WithAttributes(attrs...))
	metrics.aclLatency.Record(ctx, latencyMs, metric.WithAttributes(attrs...))
}

// RecordACLDenied records a denied ACL check
func RecordACLDenied(ctx context.Context, backend string, topic string, access string, latencyMs float64) {
	if metrics == nil {
		return
	}
	attrs := []attribute.KeyValue{
		attribute.String("backend", backend),
		attribute.String("access", access),
	}
	metrics.aclDenied.Add(ctx, 1, metric.WithAttributes(attrs...))
	metrics.aclLatency.Record(ctx, latencyMs, metric.WithAttributes(attrs...))
}

// RecordSuperuserCheck records a superuser check
func RecordSuperuserCheck(ctx context.Context, backend string, granted bool) {
	if metrics == nil {
		return
	}
	attrs := []attribute.KeyValue{
		attribute.String("backend", backend),
	}
	metrics.superuserChecks.Add(ctx, 1, metric.WithAttributes(attrs...))
	if granted {
		metrics.superuserGranted.Add(ctx, 1, metric.WithAttributes(attrs...))
	}
}

// RecordBackendCall records a backend call
func RecordBackendCall(ctx context.Context, backend string, operation string, latencyMs float64, err error) {
	if metrics == nil {
		return
	}
	attrs := []attribute.KeyValue{
		attribute.String("backend", backend),
		attribute.String("operation", operation),
	}
	metrics.backendCalls.Add(ctx, 1, metric.WithAttributes(attrs...))
	metrics.backendLatency.Record(ctx, latencyMs, metric.WithAttributes(attrs...))
	if err != nil {
		attrs = append(attrs, attribute.String("error", err.Error()))
		metrics.backendErrors.Add(ctx, 1, metric.WithAttributes(attrs...))
	}
}

// RecordCacheHit records a cache hit
func RecordCacheHit(ctx context.Context, cacheType string) {
	if metrics == nil {
		return
	}
	attrs := []attribute.KeyValue{
		attribute.String("type", cacheType),
	}
	metrics.cacheHits.Add(ctx, 1, metric.WithAttributes(attrs...))
}

// RecordCacheMiss records a cache miss
func RecordCacheMiss(ctx context.Context, cacheType string) {
	if metrics == nil {
		return
	}
	attrs := []attribute.KeyValue{
		attribute.String("type", cacheType),
	}
	metrics.cacheMisses.Add(ctx, 1, metric.WithAttributes(attrs...))
}

// RecordPoolStats records connection pool statistics
func RecordPoolStats(ctx context.Context, total int64, idle int64, waitTimeMs float64) {
	if metrics == nil {
		return
	}
	metrics.poolConnections.Add(ctx, total)
	metrics.poolIdleConnections.Add(ctx, idle)
	if waitTimeMs > 0 {
		metrics.poolWaitTime.Record(ctx, waitTimeMs)
	}
}

// SetHealthStatus sets the health check status
func SetHealthStatus(ctx context.Context, healthy bool) {
	if metrics == nil {
		return
	}
	var status int64
	if healthy {
		status = 1
	}
	metrics.healthCheckStatus.Record(ctx, status)
}

// Timer helps track operation latency
type Timer struct {
	start time.Time
}

// NewTimer creates a new timer
func NewTimer() *Timer {
	return &Timer{start: time.Now()}
}

// ElapsedMs returns elapsed time in milliseconds
func (t *Timer) ElapsedMs() float64 {
	return float64(time.Since(t.start).Nanoseconds()) / 1e6
}

// healthCheckHandler handles health check requests
func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	// Simple health check - could be extended to check backend connectivity
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}