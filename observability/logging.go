package observability

import (
	"context"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/trace"
)

// ContextKey is a type for context keys
type ContextKey string

const (
	// Context keys for logging
	RequestIDKey   ContextKey = "request_id"
	UsernameKey    ContextKey = "username"
	ClientIDKey    ContextKey = "client_id"
	BackendKey     ContextKey = "backend"
	TopicKey       ContextKey = "topic"
	AccessTypeKey  ContextKey = "access_type"
	OperationKey   ContextKey = "operation"
)

// LogEntry represents a structured log entry with context
type LogEntry struct {
	logger *log.Entry
}

// NewLogEntry creates a new log entry with context
func NewLogEntry(ctx context.Context) *LogEntry {
	entry := log.NewEntry(log.StandardLogger())

	// Add trace ID if available
	if span := trace.SpanFromContext(ctx); span.SpanContext().IsValid() {
		entry = entry.WithField("trace_id", span.SpanContext().TraceID().String())
		entry = entry.WithField("span_id", span.SpanContext().SpanID().String())
	}

	// Add context values
	if requestID := ctx.Value(RequestIDKey); requestID != nil {
		entry = entry.WithField("request_id", requestID)
	}

	if username := ctx.Value(UsernameKey); username != nil {
		entry = entry.WithField("username", username)
	}

	if clientID := ctx.Value(ClientIDKey); clientID != nil {
		entry = entry.WithField("client_id", clientID)
	}

	if backend := ctx.Value(BackendKey); backend != nil {
		entry = entry.WithField("backend", backend)
	}

	if topic := ctx.Value(TopicKey); topic != nil {
		entry = entry.WithField("topic", topic)
	}

	if accessType := ctx.Value(AccessTypeKey); accessType != nil {
		entry = entry.WithField("access_type", accessType)
	}

	if operation := ctx.Value(OperationKey); operation != nil {
		entry = entry.WithField("operation", operation)
	}

	return &LogEntry{logger: entry}
}

// WithField adds a field to the log entry
func (l *LogEntry) WithField(key string, value interface{}) *LogEntry {
	l.logger = l.logger.WithField(key, value)
	return l
}

// WithFields adds multiple fields to the log entry
func (l *LogEntry) WithFields(fields map[string]interface{}) *LogEntry {
	l.logger = l.logger.WithFields(fields)
	return l
}

// WithError adds an error to the log entry
func (l *LogEntry) WithError(err error) *LogEntry {
	l.logger = l.logger.WithError(err)
	return l
}

// WithDuration adds a duration field to the log entry
func (l *LogEntry) WithDuration(start time.Time) *LogEntry {
	duration := time.Since(start)
	l.logger = l.logger.WithField("duration_ms", duration.Milliseconds())
	return l
}

// Debug logs a debug message
func (l *LogEntry) Debug(msg string) {
	l.logger.Debug(msg)
}

// Debugf logs a formatted debug message
func (l *LogEntry) Debugf(format string, args ...interface{}) {
	l.logger.Debugf(format, args...)
}

// Info logs an info message
func (l *LogEntry) Info(msg string) {
	l.logger.Info(msg)
}

// Infof logs a formatted info message
func (l *LogEntry) Infof(format string, args ...interface{}) {
	l.logger.Infof(format, args...)
}

// Warn logs a warning message
func (l *LogEntry) Warn(msg string) {
	l.logger.Warn(msg)
}

// Warnf logs a formatted warning message
func (l *LogEntry) Warnf(format string, args ...interface{}) {
	l.logger.Warnf(format, args...)
}

// Error logs an error message
func (l *LogEntry) Error(msg string) {
	l.logger.Error(msg)
}

// Errorf logs a formatted error message
func (l *LogEntry) Errorf(format string, args ...interface{}) {
	l.logger.Errorf(format, args...)
}

// ContextWithValues creates a new context with common values
func ContextWithValues(ctx context.Context, username, clientID, backend string) context.Context {
	ctx = context.WithValue(ctx, UsernameKey, username)
	ctx = context.WithValue(ctx, ClientIDKey, clientID)
	ctx = context.WithValue(ctx, BackendKey, backend)
	return ctx
}

// ContextWithRequestID adds a request ID to the context
func ContextWithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, RequestIDKey, requestID)
}

// ContextWithOperation adds an operation name to the context
func ContextWithOperation(ctx context.Context, operation string) context.Context {
	return context.WithValue(ctx, OperationKey, operation)
}

// ContextWithTopic adds a topic to the context
func ContextWithTopic(ctx context.Context, topic string) context.Context {
	return context.WithValue(ctx, TopicKey, topic)
}

// ContextWithAccessType adds an access type to the context
func ContextWithAccessType(ctx context.Context, accessType string) context.Context {
	return context.WithValue(ctx, AccessTypeKey, accessType)
}

// GetAccessTypeString converts access integer to string
func GetAccessTypeString(access int) string {
	switch access {
	case 1:
		return "read"
	case 2:
		return "write"
	case 3:
		return "readwrite"
	case 4:
		return "subscribe"
	default:
		return fmt.Sprintf("unknown_%d", access)
	}
}

// InitializeLogging configures the logging system
func InitializeLogging(level string, destination string, file string) error {
	// Set log level
	parsedLevel, err := log.ParseLevel(level)
	if err != nil {
		return fmt.Errorf("invalid log level '%s': %w", level, err)
	}
	log.SetLevel(parsedLevel)

	// Set log formatter (JSON for structured logging)
	log.SetFormatter(&log.JSONFormatter{
		TimestampFormat: time.RFC3339Nano,
		FieldMap: log.FieldMap{
			log.FieldKeyTime:  "timestamp",
			log.FieldKeyLevel: "level",
			log.FieldKeyMsg:   "message",
		},
	})

	// Set log output
	switch destination {
	case "stdout":
		// Already the default
	case "stderr":
		log.SetOutput(log.StandardLogger().Out)
	case "file":
		if file == "" {
			return fmt.Errorf("log file path not specified")
		}
		// File logging would be configured here
		// For simplicity, we'll just log a warning
		log.Warnf("File logging not fully implemented, using stdout")
	default:
		return fmt.Errorf("invalid log destination '%s'", destination)
	}

	return nil
}