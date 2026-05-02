package api

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"time"
)

// requestIDKey is the context key for the request ID.
type requestIDKey struct{}

// GenerateRequestID creates a unique request ID using timestamp + random bytes.
func GenerateRequestID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%d-%x", time.Now().UnixNano(), b)
}

// RequestIDFromContext extracts the request ID from the context.
// Returns an empty string if no request ID is set.
func RequestIDFromContext(ctx context.Context) string {
	if id, ok := ctx.Value(requestIDKey{}).(string); ok {
		return id
	}
	return ""
}

// ContextWithRequestID returns a new context with the given request ID.
func ContextWithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

// requestIDMiddleware wraps an http.Handler to inject an X-Request-ID header
// into every response and store the request ID in the request context.
func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := GenerateRequestID()
		w.Header().Set("X-Request-ID", id)
		ctx := ContextWithRequestID(r.Context(), id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
