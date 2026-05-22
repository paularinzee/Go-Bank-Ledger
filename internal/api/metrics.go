package api

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	// TransactionLatency tracks how long deposits, withdrawals, and transfers take
	TransactionLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "ledger_transaction_duration_seconds",
			Help:    "Latency of ledger transaction executions in seconds.",
			Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0}, // Tailored for sub-second database transactions
		},
		[]string{"operation"}, // e.g., "deposit", "withdraw", "transfer"
	)

	// TransactionCount tracks execution frequency categorized by operation and status code outcome
	TransactionCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ledger_transactions_total",
			Help: "Total count of ledger transaction execution attempts.",
		},
		[]string{"operation", "status"}, // e.g., status="success", status="error_insufficient_funds", status="error_internal"
	)
)

func init() {
	// Register metrics with Prometheus's default registry
	prometheus.MustRegister(TransactionLatency)
	prometheus.MustRegister(TransactionCount)
}
