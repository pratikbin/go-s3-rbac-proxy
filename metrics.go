package main

import (
	"github.com/prometheus/client_golang/prometheus"
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

	requestMetricsQueue = make(chan requestMetricsEvent, metricsQueueSize)
	dataTransferQueue   = make(chan dataTransferEvent, metricsQueueSize)
	backendLatencyQueue = make(chan backendLatencyEvent, metricsQueueSize)
)

func init() {
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
