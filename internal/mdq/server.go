package mdq

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sirosfoundation/goff/internal/pipeline"
	"github.com/sirosfoundation/goff/internal/repo"
)

type handlerConfig struct {
	isReady         func() bool
	extraMetrics    func() map[string]any
	requestCounters *RequestCounters
	aggregateCfg    pipeline.AggregateConfig
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

// WithAggregateConfig sets the SAML aggregate metadata attributes
// (Name, CacheDuration, ValidUntil) applied to XML responses.
// The @Name is overridden per-request by the base URL if one is configured
// or can be detected from proxy headers.
func WithAggregateConfig(ac pipeline.AggregateConfig) HandlerOption {
	return func(cfg *handlerConfig) {
		cfg.aggregateCfg = ac
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

	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		cfg.requestCounters.RequestsTotal.Add(1)
		cfg.requestCounters.MetricsRequests.Add(1)

		payload := map[string]any{
			"requests": map[string]uint64{
				"total":               cfg.requestCounters.RequestsTotal.Load(),
				"healthz":             cfg.requestCounters.HealthzRequests.Load(),
				"readyz":              cfg.requestCounters.ReadyzRequests.Load(),
				"metrics":             cfg.requestCounters.MetricsRequests.Load(),
				"entities_list":       cfg.requestCounters.EntitiesListRequests.Load(),
				"entity_lookup":       cfg.requestCounters.EntityLookupRequests.Load(),
				"entity_lookup_404":   cfg.requestCounters.EntityLookupNotFound.Load(),
				"entity_lookup_400":   cfg.requestCounters.EntityLookupBadInput.Load(),
				"entity_lookup_406":   cfg.requestCounters.EntityLookupNotAccept.Load(),
						"entity_list_406":     cfg.requestCounters.EntityListNotAccept.Load(),
			},
		}

		for k, v := range cfg.extraMetrics() {
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
			ac := cfg.aggregateCfg
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
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"entityID": entityID})
		case "xml":
			setCacheHeaders(w, cfg.aggregateCfg)
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

	return mux
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
	if strings.Contains(a, "application/json") {
		return "json"
	}
	if strings.Contains(a, "application/samlmetadata+xml") || strings.Contains(a, "application/xml") || strings.Contains(a, "text/xml") {
		return "xml"
	}
	return ""
}

// resolveSHA1EntityID resolves a pyFF MDQ-style {sha1}HEXHASH URI to the
// stored entity ID by computing SHA1 over each known ID.  Returns ("", false)
// if the path does not use the {sha1} prefix or no match is found.
func resolveSHA1EntityID(path string, r *repo.Repository) (string, bool) {
	const prefix = "{sha1}"
	if !strings.HasPrefix(path, prefix) {
		return "", false
	}
	wantHex := strings.ToLower(strings.TrimSpace(path[len(prefix):]))
	if wantHex == "" {
		return "", false
	}
	for _, id := range r.List() {
		h := sha1.Sum([]byte(id)) //nolint:gosec // SHA1 used only for MDQ URL matching, not security
		if fmt.Sprintf("%x", h[:]) == wantHex {
			return id, true
		}
	}
	return "", false
}

// entityETag returns a quoted ETag value for an XML entity body derived from
// the first 8 bytes of its SHA-256 digest.
func entityETag(body string) string {
	h := sha256.Sum256([]byte(body))
	return fmt.Sprintf(`"%x"`, h[:8])
}

func renderEntityXML(entityID string) string {
	return fmt.Sprintf("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"%s\"></md:EntityDescriptor>\n", entityID)
}

// resolveAggregateName returns the @Name value for the /entities aggregate
// response.  Priority: explicit baseURL config → X-Forwarded-* headers → Host.
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
	return cfg.aggregateCfg.Name
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

type xmlGetter interface {
	List() []string
	Get(entityID string) (string, bool)
}
