package server

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type metrics struct {
	requests     *prometheus.CounterVec
	authFailures *prometheus.CounterVec
	denials      *prometheus.CounterVec
	duration     *prometheus.HistogramVec
	inflight     prometheus.Gauge
}

func newMetrics(reg prometheus.Registerer) *metrics {
	f := promauto.With(reg)
	return &metrics{
		requests: f.NewCounterVec(prometheus.CounterOpts{
			Name: "mcp_proxy_requests_total",
			Help: "Total HTTP requests handled by the MCP OAuth proxy.",
		}, []string{"method", "outcome", "code"}),
		authFailures: f.NewCounterVec(prometheus.CounterOpts{
			Name: "mcp_proxy_auth_failures_total",
			Help: "Access tokens rejected during authentication.",
		}, []string{"reason"}),
		denials: f.NewCounterVec(prometheus.CounterOpts{
			Name: "mcp_proxy_policy_denials_total",
			Help: "MCP requests denied by the authorization policy.",
		}, []string{"mcp_method", "rule"}),
		duration: f.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "mcp_proxy_request_duration_seconds",
			Help:    "End-to-end request latency, including the upstream MCP server.",
			Buckets: prometheus.DefBuckets,
		}, []string{"outcome"}),
		inflight: f.NewGauge(prometheus.GaugeOpts{
			Name: "mcp_proxy_inflight_requests",
			Help: "Requests currently being proxied, including open SSE streams.",
		}),
	}
}

// graphCollector exposes the directory cache counters. They are read at scrape
// time from the resolvers themselves, so the hot path stays free of any
// metrics bookkeeping beyond the counters it already keeps.
type graphCollector struct {
	dir     *directory
	lookups *prometheus.Desc
}

func newGraphCollector(dir *directory) *graphCollector {
	return &graphCollector{
		dir: dir,
		lookups: prometheus.NewDesc(
			"mcp_proxy_graph_lookups_total",
			"Microsoft Graph group lookups by cache outcome.",
			[]string{"result"}, nil,
		),
	}
}

func (c *graphCollector) Describe(ch chan<- *prometheus.Desc) { ch <- c.lookups }

func (c *graphCollector) Collect(ch chan<- prometheus.Metric) {
	s := c.dir.resolver.Stats()
	for result, v := range map[string]int64{
		"hit":   s.Hits,
		"miss":  s.Misses,
		"stale": s.Stale,
		"error": s.Errors,
	} {
		ch <- prometheus.MustNewConstMetric(c.lookups, prometheus.CounterValue, float64(v), result)
	}
}
