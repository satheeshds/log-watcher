package main

import (
	"testing"

	"github.com/docker/docker/api/types/events"
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
