package mdq

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"

	"github.com/sirosfoundation/goff/internal/repo"
)

type handlerConfig struct {
	isReady         func() bool
	extraMetrics    func() map[string]any
	requestCounters *RequestCounters
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
		format := resolveFormat(req.Header.Get("Accept"), "")
		if format == "xml" {
			w.Header().Set("Content-Type", "application/samlmetadata+xml")
			_, _ = w.Write([]byte(renderEntitiesXML(r.List(), r)))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string][]string{"entities": r.List()})
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
			w.Header().Set("Content-Type", "application/samlmetadata+xml")
			if body, ok := r.Get(entityID); ok {
				_, _ = w.Write([]byte(body))
			} else {
				_, _ = w.Write([]byte(renderEntityXML(entityID)))
			}
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

func renderEntityXML(entityID string) string {
	return fmt.Sprintf("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"%s\"></md:EntityDescriptor>\n", entityID)
}

type xmlGetter interface {
	List() []string
	Get(entityID string) (string, bool)
}

func renderEntitiesXML(ids []string, r xmlGetter) string {
	var sb strings.Builder
	sb.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
	sb.WriteString("<md:EntitiesDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\">\n")
	for _, id := range ids {
		if body, ok := r.Get(id); ok {
			// strip XML declaration if present so it embeds cleanly
			body = strings.TrimPrefix(body, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
			body = strings.TrimPrefix(body, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>")
			sb.WriteString(body)
			if !strings.HasSuffix(strings.TrimSpace(body), "\n") {
				sb.WriteByte('\n')
			}
		} else {
			sb.WriteString(fmt.Sprintf("  <md:EntityDescriptor entityID=\"%s\"></md:EntityDescriptor>\n", id))
		}
	}
	sb.WriteString("</md:EntitiesDescriptor>\n")
	return sb.String()
}
