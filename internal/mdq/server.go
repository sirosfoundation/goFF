package mdq

import (
	"crypto/sha256"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sirosfoundation/goff/internal/pipeline"
	"github.com/sirosfoundation/goff/internal/repo"
)

// logger returns the default structured logger used by the MDQ server.
// Callers can replace the default by calling slog.SetDefault before starting.
func logger() *slog.Logger { return slog.Default() }

type handlerConfig struct {
	isReady         func() bool
	extraMetrics    func() map[string]any
	requestCounters *RequestCounters
	// aggregateCfg is called per-request to obtain the current SAML aggregate
	// parameters.  This allows the values to be updated atomically on refresh
	// without restarting the server.
	aggregateCfg func() pipeline.AggregateConfig
	// discoJSON, when non-nil, returns the current discovery-service JSON feed
	// entries.  The /entities endpoint serves this when the client sends
	// Accept: application/disco+json.  Nil means no disco feed is available.
	discoJSON func() []pipeline.DiscoEntry
	// entityRenderer is called per-request to obtain the strategy for serializing
	// a single entity to JSON (/entities/{id} with Accept: application/json).
	// Defaults to MinimalRenderer when nil.
	entityRenderer func() EntityRenderer
	// baseURL is the externally-visible base URL of this server, used to
	// derive @Name on the EntitiesDescriptor for aggregate responses.
	// If empty the value is detected from X-Forwarded-* / Host headers.
	baseURL string
}

// HandlerOption customizes MDQ handler behavior.
type HandlerOption func(*handlerConfig)

// RequestCounters tracks basic operational request metrics.
type RequestCounters struct {
	RequestsTotal         atomic.Uint64
	HealthzRequests       atomic.Uint64
	ReadyzRequests        atomic.Uint64
	MetricsRequests       atomic.Uint64
	EntitiesListRequests  atomic.Uint64
	EntityListNotAccept   atomic.Uint64
	EntityLookupRequests  atomic.Uint64
	EntityLookupNotFound  atomic.Uint64
	EntityLookupBadInput  atomic.Uint64
	EntityLookupNotAccept atomic.Uint64
}

// WithReadiness configures readiness semantics for /readyz.
func WithReadiness(fn func() bool) HandlerOption {
	return func(cfg *handlerConfig) {
		cfg.isReady = fn
	}
}

// WithExtraMetrics injects additional metrics payload fields into /metrics.
func WithExtraMetrics(fn func() map[string]any) HandlerOption {
	return func(cfg *handlerConfig) {
		cfg.extraMetrics = fn
	}
}

// WithRequestCounters allows sharing counters with callers.
func WithRequestCounters(c *RequestCounters) HandlerOption {
	return func(cfg *handlerConfig) {
		cfg.requestCounters = c
	}
}

// WithAggregateConfig sets static SAML aggregate metadata attributes
// (Name, CacheDuration, ValidUntil) applied to XML responses.
// For dynamic updates (e.g. after pipeline reload) use WithAggregateConfigFunc.
func WithAggregateConfig(ac pipeline.AggregateConfig) HandlerOption {
	return func(cfg *handlerConfig) {
		cfg.aggregateCfg = func() pipeline.AggregateConfig { return ac }
	}
}

// WithAggregateConfigFunc sets a dynamic aggregate config provider.  The
// function is called on every request, so atomic.Pointer-backed closures are
// safe to use here.
func WithAggregateConfigFunc(fn func() pipeline.AggregateConfig) HandlerOption {
	return func(cfg *handlerConfig) {
		cfg.aggregateCfg = fn
	}
}

// WithDiscoJSON configures the /entities endpoint to serve a discovery-service
// JSON feed when the client sends Accept: application/disco+json.  The function
// is called per-request; use an atomic.Pointer-backed closure for safe dynamic
// updates after pipeline refresh.
func WithDiscoJSON(fn func() []pipeline.DiscoEntry) HandlerOption {
	return func(cfg *handlerConfig) {
		cfg.discoJSON = fn
	}
}

// WithEntityRenderer sets a static EntityRenderer for /entities/{id} JSON responses.
func WithEntityRenderer(r EntityRenderer) HandlerOption {
	return func(cfg *handlerConfig) {
		cfg.entityRenderer = func() EntityRenderer { return r }
	}
}

// WithEntityRendererFunc sets a dynamic EntityRenderer provider for /entities/{id}
// JSON responses.  The function is called on every matching request, so an
// atomic.Pointer-backed closure is safe for live updates after pipeline refresh.
func WithEntityRendererFunc(fn func() EntityRenderer) HandlerOption {
	return func(cfg *handlerConfig) {
		cfg.entityRenderer = fn
	}
}

// WithBaseURL sets the externally-visible base URL of this server
// (e.g. "https://mdq.example.org").  The @Name attribute on the
// /entities aggregate response is derived as baseURL+"/entities".
// If empty, the value is auto-detected from X-Forwarded-Proto / X-Forwarded-Host
// / Host request headers.
func WithBaseURL(u string) HandlerOption {
	return func(cfg *handlerConfig) {
		cfg.baseURL = strings.TrimRight(u, "/")
	}
}

// NewHandler returns the HTTP handler for a minimal MDQ-like API.
func NewHandler(r *repo.Repository, opts ...HandlerOption) http.Handler {
	cfg := &handlerConfig{
		isReady:         func() bool { return true },
		extraMetrics:    func() map[string]any { return map[string]any{} },
		requestCounters: &RequestCounters{},
		aggregateCfg:    func() pipeline.AggregateConfig { return pipeline.AggregateConfig{} },
		entityRenderer:  func() EntityRenderer { return MinimalRenderer{} },
	}
	for _, opt := range opts {
		opt(cfg)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		cfg.requestCounters.RequestsTotal.Add(1)
		cfg.requestCounters.HealthzRequests.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})

	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		cfg.requestCounters.RequestsTotal.Add(1)
		cfg.requestCounters.ReadyzRequests.Add(1)
		if !cfg.isReady() {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready\n"))
	})

	mux.HandleFunc("/metrics", func(w http.ResponseWriter, req *http.Request) {
		cfg.requestCounters.RequestsTotal.Add(1)
		cfg.requestCounters.MetricsRequests.Add(1)

		extra := cfg.extraMetrics()

		// Prometheus text format when Accept: text/plain (or explicit openmetrics).
		if wantsPrometheus(req.Header.Get("Accept")) {
			w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
			rc := cfg.requestCounters
			writePrometheusCounters(w, rc, extra)
			return
		}

		payload := map[string]any{
			"requests": map[string]uint64{
				"total":             cfg.requestCounters.RequestsTotal.Load(),
				"healthz":           cfg.requestCounters.HealthzRequests.Load(),
				"readyz":            cfg.requestCounters.ReadyzRequests.Load(),
				"metrics":           cfg.requestCounters.MetricsRequests.Load(),
				"entities_list":     cfg.requestCounters.EntitiesListRequests.Load(),
				"entity_lookup":     cfg.requestCounters.EntityLookupRequests.Load(),
				"entity_lookup_404": cfg.requestCounters.EntityLookupNotFound.Load(),
				"entity_lookup_400": cfg.requestCounters.EntityLookupBadInput.Load(),
				"entity_lookup_406": cfg.requestCounters.EntityLookupNotAccept.Load(),
				"entity_list_406":   cfg.requestCounters.EntityListNotAccept.Load(),
			},
		}

		for k, v := range extra {
			payload[k] = v
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(payload)
	})

	mux.HandleFunc("/entities", func(w http.ResponseWriter, req *http.Request) {
		cfg.requestCounters.RequestsTotal.Add(1)
		cfg.requestCounters.EntitiesListRequests.Add(1)
		// Resolve format; default to JSON when no Accept header is provided
		// (preserves backward-compatible behaviour for clients that do not
		// set Accept).  Return 406 for an explicit but unsupported type.
		format := resolveListFormat(req.Header.Get("Accept"))
		switch format {
		case "xml":
			ac := cfg.aggregateCfg()
			ac.Name = resolveAggregateName(cfg, req)
			setCacheHeaders(w, ac)
			w.Header().Set("Content-Type", "application/samlmetadata+xml")
			ids := r.List()
			bodies := make(map[string]string, len(ids))
			for _, id := range ids {
				if body, ok := r.Get(id); ok {
					bodies[id] = body
				}
			}
			_, _ = w.Write(pipeline.BuildEntitiesXML(ids, bodies, ac))
		case "disco":
			if cfg.discoJSON == nil {
				// No disco feed configured; fall back to entity ID list.
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string][]string{"entities": r.List()})
				return
			}
			entries := cfg.discoJSON()
			if entries == nil {
				entries = []pipeline.DiscoEntry{}
			}
			w.Header().Set("Content-Type", "application/disco+json")
			_ = json.NewEncoder(w).Encode(entries)
		case "json":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string][]string{"entities": r.List()})
		default:
			cfg.requestCounters.EntityListNotAccept.Add(1)
			http.Error(w, "not acceptable", http.StatusNotAcceptable)
		}
	})

	mux.HandleFunc("/entities/", func(w http.ResponseWriter, req *http.Request) {
		cfg.requestCounters.RequestsTotal.Add(1)
		cfg.requestCounters.EntityLookupRequests.Add(1)

		rawID := strings.TrimPrefix(req.URL.Path, "/entities/")
		if rawID == "" {
			cfg.requestCounters.EntityLookupBadInput.Add(1)
			http.Error(w, "missing entity id", http.StatusBadRequest)
			return
		}

		entityPath, fromExt := splitEntityPath(rawID)

		entityID, err := url.PathUnescape(entityPath)
		if err != nil {
			cfg.requestCounters.EntityLookupBadInput.Add(1)
			http.Error(w, "invalid entity id", http.StatusBadRequest)
			return
		}

		// Support pyFF MDQ {sha1}HEXHASH lookup form.
		if resolved, ok := resolveSHA1EntityID(entityID, r); ok {
			entityID = resolved
		}

		if !r.Has(entityID) {
			cfg.requestCounters.EntityLookupNotFound.Add(1)
			http.Error(w, "entity not found", http.StatusNotFound)
			return
		}

		format := resolveFormat(req.Header.Get("Accept"), fromExt)
		switch format {
		case "json":
			renderer := cfg.entityRenderer()
			var xmlBody string
			if body, ok := r.Get(entityID); ok {
				xmlBody = body
			}
			data, err := renderer.RenderEntity(entityID, xmlBody)
			if err != nil {
				http.Error(w, "render error", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", renderer.ContentType())
			_, _ = w.Write(data)
		case "xml":
			setCacheHeaders(w, cfg.aggregateCfg())
			w.Header().Set("Content-Type", "application/samlmetadata+xml")
			var xmlBody string
			if body, ok := r.Get(entityID); ok {
				xmlBody = body
			} else {
				xmlBody = renderEntityXML(entityID)
			}
			etag := entityETag(xmlBody)
			w.Header().Set("ETag", etag)
			if req.Header.Get("If-None-Match") == etag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			_, _ = w.Write([]byte(xmlBody))
		default:
			cfg.requestCounters.EntityLookupNotAccept.Add(1)
			http.Error(w, "not acceptable", http.StatusNotAcceptable)
		}
	})

	return securityHeaders(accessLog(mux))
}

// securityHeaders adds conservative HTTP security headers to every response.
// When the connection uses TLS (r.TLS != nil), HSTS is also included.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		// MDQ serves only machine-readable XML/JSON; a deny-all CSP is safe.
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

// accessLog logs each request to the standard logger after it completes.
func accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &statusRecorder{ResponseWriter: w, code: http.StatusOK}
		next.ServeHTTP(rw, r)
		logger().Info("http",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rw.code,
			"duration_ms", time.Since(start).Milliseconds(),
			"remote", r.RemoteAddr,
		)
	})
}

// statusRecorder wraps ResponseWriter to capture the status code.
type statusRecorder struct {
	http.ResponseWriter
	code int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.code = code
	r.ResponseWriter.WriteHeader(code)
}

func splitEntityPath(raw string) (entityPath string, fromExt string) {
	if strings.HasSuffix(raw, ".xml") {
		return strings.TrimSuffix(raw, ".xml"), "xml"
	}
	if strings.HasSuffix(raw, ".json") {
		return strings.TrimSuffix(raw, ".json"), "json"
	}
	return raw, ""
}

func resolveFormat(accept string, fromExt string) string {
	accept = strings.ToLower(accept)
	if strings.Contains(accept, "application/json") {
		return "json"
	}
	if strings.Contains(accept, "application/samlmetadata+xml") || strings.Contains(accept, "application/xml") || strings.Contains(accept, "text/xml") {
		return "xml"
	}

	if fromExt != "" {
		return fromExt
	}

	if accept == "" || strings.Contains(accept, "*/*") || strings.Contains(accept, "application/*") || strings.Contains(accept, "text/*") {
		return "xml"
	}

	return ""
}

// resolveListFormat resolves the response format for the /entities aggregate
// list endpoint.  When no Accept header is present the default is JSON
// (backward-compatible).  An explicit but unsupported type returns "".
func resolveListFormat(accept string) string {
	a := strings.ToLower(accept)
	if a == "" || strings.Contains(a, "*/*") || strings.Contains(a, "application/*") || strings.Contains(a, "text/*") {
		return "json"
	}
	if strings.Contains(a, "application/disco+json") {
		return "disco"
	}
	if strings.Contains(a, "application/json") {
		return "json"
	}
	if strings.Contains(a, "application/samlmetadata+xml") || strings.Contains(a, "application/xml") || strings.Contains(a, "text/xml") {
		return "xml"
	}
	return ""
}

// resolveSHA1EntityID resolves a pyFF MDQ-style {sha1}HEXHASH URI to the
// stored entity ID using the repository's pre-built O(1) SHA-1 index.
// Returns ("", false) if the path does not use the {sha1} prefix or no match
// is found.
func resolveSHA1EntityID(path string, r *repo.Repository) (string, bool) {
	const prefix = "{sha1}"
	if !strings.HasPrefix(path, prefix) {
		return "", false
	}
	wantHex := strings.ToLower(strings.TrimSpace(path[len(prefix):]))
	if wantHex == "" {
		return "", false
	}
	return r.ResolveSHA1(wantHex)
}

// entityETag returns a quoted ETag value for an XML entity body derived from
// the first 8 bytes of its SHA-256 digest.
func entityETag(body string) string {
	h := sha256.Sum256([]byte(body))
	return fmt.Sprintf(`"%x"`, h[:8])
}

func renderEntityXML(entityID string) string {
	var buf strings.Builder
	buf.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
	buf.WriteString(`<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="`)
	_ = xml.EscapeText(&buf, []byte(entityID))
	buf.WriteString(`"></md:EntityDescriptor>` + "\n")
	return buf.String()
}

// resolveAggregateName returns the @Name value for the /entities aggregate
// response.  Priority: explicit baseURL config → X-Forwarded-* headers → Host.
//
// Production deployments should always set --base-url / GOFF_BASE_URL to avoid
// relying on X-Forwarded-Host and X-Forwarded-Prefix headers from potentially
// untrusted reverse proxies.  The returned value is XML-attribute-escaped by
// BuildEntitiesXML before being written into the document.
func resolveAggregateName(cfg *handlerConfig, req *http.Request) string {
	if cfg.baseURL != "" {
		return cfg.baseURL + "/entities"
	}
	proto := req.Header.Get("X-Forwarded-Proto")
	host := req.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = req.Host
	}
	if proto == "" {
		if req.TLS != nil {
			proto = "https"
		} else {
			proto = "http"
		}
	}
	if host != "" {
		prefix := strings.TrimRight(req.Header.Get("X-Forwarded-Prefix"), "/")
		return proto + "://" + host + prefix + "/entities"
	}
	return cfg.aggregateCfg().Name
}

// setCacheHeaders writes Cache-Control and Expires headers derived from
// the AggregateConfig CacheDuration and ValidUntil fields.
func setCacheHeaders(w http.ResponseWriter, ac pipeline.AggregateConfig) {
	validUntil := pipeline.ResolveValidUntil(ac.ValidUntil)
	if validUntil != "" {
		if t, err := time.Parse(time.RFC3339, validUntil); err == nil {
			w.Header().Set("Expires", t.UTC().Format(http.TimeFormat))
			if maxAge := int(time.Until(t).Seconds()); maxAge > 0 {
				w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", maxAge))
			}
		}
	}
	if ac.CacheDuration != "" && w.Header().Get("Cache-Control") == "" {
		if secs, ok := pipeline.ParseCacheDurationSeconds(ac.CacheDuration); ok {
			w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", secs))
		}
	}
}

// wantsPrometheus returns true if the Accept header indicates the client can
// accept Prometheus text exposition format.
func wantsPrometheus(accept string) bool {
	a := strings.ToLower(accept)
	return strings.Contains(a, "text/plain") ||
		strings.Contains(a, "application/openmetrics-text")
}

// writePrometheusCounters writes request counter metrics to w in the
// Prometheus text exposition format (version 0.0.4).
func writePrometheusCounters(w http.ResponseWriter, rc *RequestCounters, extra map[string]any) {
	type labeledCounter struct {
		endpoint string
		value    uint64
	}
	counters := []labeledCounter{
		{"healthz", rc.HealthzRequests.Load()},
		{"readyz", rc.ReadyzRequests.Load()},
		{"metrics", rc.MetricsRequests.Load()},
		{"entities_list", rc.EntitiesListRequests.Load()},
		{"entity_lookup", rc.EntityLookupRequests.Load()},
	}
	pw := func(format string, args ...any) { _, _ = fmt.Fprintf(w, format, args...) }
	pw("# HELP goff_requests_total Total HTTP requests by endpoint.\n")
	pw("# TYPE goff_requests_total counter\n")
	for _, c := range counters {
		pw("goff_requests_total{endpoint=%q} %d\n", c.endpoint, c.value)
	}
	pw("# HELP goff_http_errors_total HTTP error responses by status code.\n")
	pw("# TYPE goff_http_errors_total counter\n")
	pw("goff_http_errors_total{code=\"404\"} %d\n", rc.EntityLookupNotFound.Load())
	pw("goff_http_errors_total{code=\"400\"} %d\n", rc.EntityLookupBadInput.Load())
	pw("goff_http_errors_total{code=\"406\"} %d\n", rc.EntityLookupNotAccept.Load()+rc.EntityListNotAccept.Load())

	// Expose extra metrics (refresh, entity_count) as gauges.
	if refresh, ok := extra["refresh"].(map[string]any); ok {
		if v, ok := refresh["entity_count"]; ok {
			pw("# HELP goff_entity_count Number of entities in the current repository.\n")
			pw("# TYPE goff_entity_count gauge\n")
			pw("goff_entity_count %v\n", v)
		}
		if v, ok := refresh["success_total"]; ok {
			pw("# HELP goff_refresh_success_total Total successful pipeline refresh runs.\n")
			pw("# TYPE goff_refresh_success_total counter\n")
			pw("goff_refresh_success_total %v\n", v)
		}
		if v, ok := refresh["failure_total"]; ok {
			pw("# HELP goff_refresh_failure_total Total failed pipeline refresh runs.\n")
			pw("# TYPE goff_refresh_failure_total counter\n")
			pw("goff_refresh_failure_total %v\n", v)
		}
		if v, ok := refresh["stale_since_unix"]; ok {
			pw("# HELP goff_stale_since_unix Unix timestamp of first consecutive refresh failure (0 = healthy).\n")
			pw("# TYPE goff_stale_since_unix gauge\n")
			pw("goff_stale_since_unix %v\n", v)
		}
	}
}
