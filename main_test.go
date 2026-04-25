package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/docker/docker/api/types/events"
	"github.com/redis/go-redis/v9"
)

func TestShouldMonitorContainer(t *testing.T) {
	tests := []struct {
		name   string
		labels map[string]string
		want   bool
	}{
		{name: "monitored", labels: map[string]string{monitorLabel: "true"}, want: true},
		{name: "missing label", labels: map[string]string{}, want: false},
		{name: "false label", labels: map[string]string{monitorLabel: "false"}, want: false},
	}

	for _, tt := range tests {
		if got := shouldMonitorContainer(tt.labels); got != tt.want {
			t.Fatalf("%s: got %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestShouldWatchContainerEvent(t *testing.T) {
	for _, action := range []events.Action{events.ActionStart, events.ActionRestart, events.ActionUnPause} {
		if !shouldWatchContainerEvent(action) {
			t.Fatalf("expected %q to trigger log watching", action)
		}
	}

	for _, action := range []events.Action{events.ActionStop, events.ActionDie, events.ActionDestroy, events.ActionPause} {
		if shouldWatchContainerEvent(action) {
			t.Fatalf("expected %q not to trigger log watching", action)
		}
	}
}

func TestNormalizeLogLine(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "ISO 8601 timestamp with Z",
			input: "2024-01-15T10:30:45.123Z ERROR: connection refused",
			want:  "<TIMESTAMP> ERROR: connection refused",
		},
		{
			name:  "ISO 8601 timestamp with timezone offset",
			input: "2024-01-15T10:30:45+05:30 ERROR: disk full",
			want:  "<TIMESTAMP> ERROR: disk full",
		},
		{
			name:  "ISO 8601 timestamp with space separator",
			input: "2024-01-15 10:30:45.000 ERROR: out of memory",
			want:  "<TIMESTAMP> ERROR: out of memory",
		},
		{
			name:  "syslog-style timestamp",
			input: "Jan 15 10:30:45 hostname app[1234]: ERROR: panic",
			want:  "<TIMESTAMP> hostname app[<NUM>]: ERROR: panic",
		},
		{
			name:  "UUID replaced",
			input: "ERROR: request 550e8400-e29b-41d4-a716-446655440000 failed",
			want:  "ERROR: request <UUID> failed",
		},
		{
			name:  "IP address replaced",
			input: "ERROR: cannot connect to 192.168.1.100:5432",
			want:  "ERROR: cannot connect to <IP>",
		},
		{
			name:  "hex trace ID replaced",
			input: "ERROR: trace=deadbeef12345678 span failed",
			want:  "ERROR: trace=<HEXID> span failed",
		},
		{
			name:  "standalone numbers replaced",
			input: "ERROR: retry 3 of 5 failed after 2000ms",
			want:  "ERROR: retry <NUM> of <NUM> failed after <NUM>ms",
		},
		{
			name:  "timestamped error message normalized",
			input: "2024-06-01T08:00:00Z ERROR: database connection failed",
			want:  "<TIMESTAMP> ERROR: database connection failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeLogLine(tt.input)
			if got != tt.want {
				t.Fatalf("normalizeLogLine(%q)\n  got  %q\n  want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestFingerprintDeduplication verifies that the same logical error with
// different timestamps produces an identical fingerprint.
func TestFingerprintDeduplication(t *testing.T) {
	container := "my-service"
	line1 := "2024-01-01T10:00:00Z ERROR: database connection failed after 3 retries"
	line2 := "2024-06-15T23:59:59.999Z ERROR: database connection failed after 3 retries"
	line3 := "2024-01-01T10:00:00Z ERROR: completely different error"

	fp := func(line string) string {
		n := normalizeLogLine(line)
		return fmt.Sprintf("%x", sha256.Sum256([]byte(container+truncate(n, 120))))
	}

	if fp(line1) != fp(line2) {
		t.Fatalf("expected same fingerprint for same error with different timestamps\n  fp1=%s\n  fp2=%s", fp(line1), fp(line2))
	}
	if fp(line1) == fp(line3) {
		t.Fatalf("expected different fingerprints for different errors")
	}
}

// newTestRedis starts an in-process miniredis server and returns a connected
// client. The server and client are both closed automatically via t.Cleanup.
func newTestRedis(t *testing.T) *redis.Client {
	t.Helper()
	s := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: s.Addr()})
	t.Cleanup(func() { rdb.Close() })
	return rdb
}

// TestRedisLockKeyPreventsRace verifies that a Redis SetNX lock key prevents a
// concurrent goroutine from acquiring the same key while it is held, which is
// the mechanism used by processAlert to avoid duplicate issue creation.
func TestRedisLockKeyPreventsRace(t *testing.T) {
	rdb := newTestRedis(t)

	containerName := "test-lock-race"
	logLine := "2024-01-01T00:00:00Z ERROR: lock race test"
	normalized := normalizeLogLine(logLine)
	fingerprint := fmt.Sprintf("%x", sha256.Sum256([]byte(containerName+truncate(normalized, 120))))
	lockKey := "watchdog:lock:" + fingerprint

	// First acquisition should succeed.
	locked1, err := rdb.SetNX(context.Background(), lockKey, "token-a", 60*time.Second).Result()
	if err != nil {
		t.Fatalf("unexpected Redis error: %v", err)
	}
	if !locked1 {
		t.Fatal("expected first SetNX to succeed")
	}

	// Second acquisition (simulating a concurrent goroutine) must fail.
	locked2, err := rdb.SetNX(context.Background(), lockKey, "token-b", 60*time.Second).Result()
	if err != nil {
		t.Fatalf("unexpected Redis error: %v", err)
	}
	if locked2 {
		t.Fatal("expected second SetNX to fail while lock is held")
	}
}
