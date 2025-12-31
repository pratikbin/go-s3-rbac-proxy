package main

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const metricsQueueSize = 1000

type requestMetricsEvent struct {
	method          string
	code            string
	bucket          string
	user            string
	durationSeconds float64
}

type dataTransferEvent struct {
	direction string
	bucket    string
	user      string
	bytes     int64
}

type backendLatencyEvent struct {
	method          string
	bucket          string
	durationSeconds float64
}

type authErrorEvent struct {
	reason string
}

type rbacDeniedEvent struct {
	user   string
	bucket string
}

var (
	// Red Metrics
	httpRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "s3_proxy_requests_total",
			Help: "Total number of HTTP requests processed, labeled by method, code, bucket, and user.",
		},
		[]string{"method", "code", "bucket", "user"},
	)

	httpRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "s3_proxy_request_duration_seconds",
			Help:    "Histogram of request duration in seconds.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "bucket"},
	)

	dataTransferBytesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "s3_proxy_data_transfer_bytes_total",
			Help: "Total number of bytes transferred through the proxy, labeled by direction, user, and bucket.",
		},
		[]string{"direction", "user", "bucket"},
	)

	backendLatencySeconds = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "s3_proxy_backend_latency_seconds",
			Help:    "Histogram of backend (Hetzner) latency in seconds.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "bucket"},
	)

	authErrorsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "s3_proxy_auth_errors_total",
			Help: "Total number of authentication errors, labeled by reason.",
		},
		[]string{"reason"},
	)

	rbacDeniedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "s3_proxy_rbac_denied_total",
			Help: "Total number of RBAC denials, labeled by user and bucket.",
		},
		[]string{"user", "bucket"},
	)

	inFlightRequests = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "s3_proxy_in_flight_requests",
		Help: "Current number of in-flight requests.",
	})

	bufferPoolRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "s3_proxy_buffer_pool_requests_total",
			Help: "Total number of buffer pool operations, labeled by action.",
		},
		[]string{"action"},
	)
	bufferPoolRequestsGet     = bufferPoolRequestsTotal.WithLabelValues("get")
	bufferPoolRequestsPut     = bufferPoolRequestsTotal.WithLabelValues("put")
	bufferPoolRequestsDiscard = bufferPoolRequestsTotal.WithLabelValues("discard")

	requestMetricsQueue = make(chan requestMetricsEvent, metricsQueueSize)
	dataTransferQueue   = make(chan dataTransferEvent, metricsQueueSize)
	backendLatencyQueue = make(chan backendLatencyEvent, metricsQueueSize)
	authErrorsQueue     = make(chan authErrorEvent, metricsQueueSize)
	rbacDeniedQueue     = make(chan rbacDeniedEvent, metricsQueueSize)
)

func init() {
	if err := prometheus.Register(collectors.NewGoCollector()); err != nil {
		if _, ok := err.(prometheus.AlreadyRegisteredError); !ok {
			panic(err)
		}
	}

	go func() {
		for event := range requestMetricsQueue {
			httpRequestsTotal.WithLabelValues(event.method, event.code, event.bucket, event.user).Inc()
			httpRequestDuration.WithLabelValues(event.method, event.bucket).Observe(event.durationSeconds)
		}
	}()
	go func() {
		for event := range dataTransferQueue {
			dataTransferBytesTotal.WithLabelValues(event.direction, event.user, event.bucket).Add(float64(event.bytes))
		}
	}()
	go func() {
		for event := range backendLatencyQueue {
			backendLatencySeconds.WithLabelValues(event.method, event.bucket).Observe(event.durationSeconds)
		}
	}()
	go func() {
		for event := range authErrorsQueue {
			authErrorsTotal.WithLabelValues(event.reason).Inc()
		}
	}()
	go func() {
		for event := range rbacDeniedQueue {
			rbacDeniedTotal.WithLabelValues(event.user, event.bucket).Inc()
		}
	}()
}

func recordRequestMetrics(method, code, bucket, user string, durationSeconds float64) {
	select {
	case requestMetricsQueue <- requestMetricsEvent{
		method:          method,
		code:            code,
		bucket:          bucket,
		user:            user,
		durationSeconds: durationSeconds,
	}:
	default:
		// Drop metrics updates when queue is full to avoid blocking requests.
	}
}

func recordDataTransfer(direction, user, bucket string, bytes int64) {
	if bytes <= 0 {
		return
	}
	select {
	case dataTransferQueue <- dataTransferEvent{
		direction: direction,
		bucket:    bucket,
		user:      user,
		bytes:     bytes,
	}:
	default:
		// Drop metrics updates when queue is full to avoid blocking requests.
	}
}

func recordBackendLatency(method, bucket string, durationSeconds float64) {
	select {
	case backendLatencyQueue <- backendLatencyEvent{
		method:          method,
		bucket:          bucket,
		durationSeconds: durationSeconds,
	}:
	default:
		// Drop metrics updates when queue is full to avoid blocking requests.
	}
}

func recordAuthError(reason string) {
	select {
	case authErrorsQueue <- authErrorEvent{reason: reason}:
	default:
		// Drop metrics updates when queue is full to avoid blocking requests.
	}
}

func recordRBACDenied(user, bucket string) {
	select {
	case rbacDeniedQueue <- rbacDeniedEvent{user: user, bucket: bucket}:
	default:
		// Drop metrics updates when queue is full to avoid blocking requests.
	}
}

func recordBufferPoolGet() {
	bufferPoolRequestsGet.Inc()
}

func recordBufferPoolPut() {
	bufferPoolRequestsPut.Inc()
}

func recordBufferPoolDiscard() {
	bufferPoolRequestsDiscard.Inc()
}
