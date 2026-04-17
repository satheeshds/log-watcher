package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/machinebox/graphql"
	"github.com/redis/go-redis/v9"
)

var (
	ctx          = context.Background()
	linearAPIKey = os.Getenv("LINEAR_API_KEY")
	linearTeamID = os.Getenv("LINEAR_TEAM_ID")
	redisAddr    = os.Getenv("REDIS_ADDR")
	// Only monitor containers with this label set to "true"
	monitorLabel       = "watchlog.monitor"
	linearProjectLabel = "linear.project"
)

type watcherState struct {
	generation int
	cancel     context.CancelFunc
}

type watcherRegistry struct {
	mu       sync.Mutex
	watchers map[string]watcherState
}

func newWatcherRegistry() *watcherRegistry {
	return &watcherRegistry{watchers: make(map[string]watcherState)}
}

func main() {
	rdb := redis.NewClient(&redis.Options{Addr: redisAddr})
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Fatalf("Docker Client Error: %v", err)
	}

	registry := newWatcherRegistry()

	log.Println("Watchlog started. Scanning running containers...")

	containers, err := cli.ContainerList(ctx, container.ListOptions{})
	if err != nil {
		log.Fatal(err)
	}

	for _, c := range containers {
		cName := strings.TrimPrefix(c.Names[0], "/")
		if !shouldMonitorContainer(c.Labels) {
			log.Printf("Skipping %s (No monitor label found)", cName)
			continue
		}

		registry.start(cli, rdb, c.ID, cName, c.Labels[linearProjectLabel])
	}

	go watchContainerEvents(cli, rdb, registry)

	select {} // Block forever
}

func (wr *watcherRegistry) start(cli *client.Client, rdb *redis.Client, containerID, name, projectLabel string) {
	wr.mu.Lock()
	current := wr.watchers[containerID]
	if current.cancel != nil {
		current.cancel()
	}

	watchCtx, cancel := context.WithCancel(context.Background())
	generation := current.generation + 1
	wr.watchers[containerID] = watcherState{generation: generation, cancel: cancel}
	wr.mu.Unlock()

	if projectLabel != "" {
		log.Printf("Monitoring logs for: %s (Linear project ID: %s)", name, projectLabel)
	} else {
		log.Printf("Monitoring logs for: %s", name)
	}

	go func(gen int) {
		defer wr.finish(containerID, gen)
		tailLogs(watchCtx, cli, rdb, containerID, name, projectLabel)
	}(generation)
}

func (wr *watcherRegistry) stop(containerID string) {
	wr.mu.Lock()
	state, ok := wr.watchers[containerID]
	if ok {
		delete(wr.watchers, containerID)
	}
	wr.mu.Unlock()

	if ok && state.cancel != nil {
		state.cancel()
	}
}

func (wr *watcherRegistry) finish(containerID string, generation int) {
	wr.mu.Lock()
	defer wr.mu.Unlock()

	state, ok := wr.watchers[containerID]
	if ok && state.generation == generation {
		delete(wr.watchers, containerID)
	}
}

func shouldMonitorContainer(labels map[string]string) bool {
	return labels[monitorLabel] == "true"
}

func shouldWatchContainerEvent(action events.Action) bool {
	switch action {
	case events.ActionStart, events.ActionRestart, events.ActionUnPause:
		return true
	default:
		return false
	}
}

func watchContainerEvents(cli *client.Client, rdb *redis.Client, registry *watcherRegistry) {
	filterArgs := filters.NewArgs(filters.Arg("type", "container"))

	for {
		messages, errs := cli.Events(ctx, events.ListOptions{Filters: filterArgs})

		streamClosed := false
		for !streamClosed {
			select {
			case msg, ok := <-messages:
				if !ok {
					streamClosed = true
					continue
				}
				handleContainerEvent(cli, rdb, registry, msg)
			case err, ok := <-errs:
				if ok && err != nil {
					log.Printf("Docker event stream error: %v", err)
				}
				streamClosed = true
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

func handleContainerEvent(cli *client.Client, rdb *redis.Client, registry *watcherRegistry, msg events.Message) {
	action := msg.Action
	containerID := msg.ID

	switch action {
	case events.ActionStop, events.ActionDie, events.ActionDestroy, events.ActionPause:
		registry.stop(containerID)
		return
	}

	if !shouldWatchContainerEvent(action) {
		return
	}

	name, projectLabel, ok := inspectMonitoredContainer(cli, containerID)
	if !ok {
		return
	}

	registry.start(cli, rdb, containerID, name, projectLabel)
}

func inspectMonitoredContainer(cli *client.Client, containerID string) (string, string, bool) {
	info, err := cli.ContainerInspect(ctx, containerID)
	if err != nil {
		log.Printf("Error inspecting container %s: %v", containerID, err)
		return "", "", false
	}

	if info.Config == nil || !shouldMonitorContainer(info.Config.Labels) {
		return "", "", false
	}

	return strings.TrimPrefix(info.Name, "/"), info.Config.Labels[linearProjectLabel], true
}

func tailLogs(watchCtx context.Context, cli *client.Client, rdb *redis.Client, containerID, name, projectLabel string) {
	options := container.LogsOptions{ShowStdout: true, ShowStderr: true, Follow: true, Tail: "0"}
	buf := make([]byte, 4096)

	for {
		if watchCtx.Err() != nil {
			return
		}

		stream, err := cli.ContainerLogs(watchCtx, containerID, options)
		if err != nil {
			if watchCtx.Err() != nil {
				return
			}
			log.Printf("Error streaming logs for %s: %v", name, err)
			select {
			case <-watchCtx.Done():
				return
			case <-time.After(2 * time.Second):
			}
			continue
		}

		func() {
			defer stream.Close()

			for {
				n, err := stream.Read(buf)
				if n > 0 {
					line := string(buf[:n])
					upperLine := strings.ToUpper(line)

					if strings.Contains(upperLine, "ERROR") || strings.Contains(upperLine, "WARNING") {
						metadata := getExtendedMetadata(cli, containerID)
						b, _ := json.MarshalIndent(metadata, "", "  ")
						processAlert(rdb, name, line, projectLabel, string(b))
					}
				}

				if err == io.EOF {
					return
				}
				if err != nil {
					if watchCtx.Err() == nil {
						log.Printf("Log stream closed for %s: %v", name, err)
					}
					return
				}
			}
		}()

		select {
		case <-watchCtx.Done():
			return
		case <-time.After(1 * time.Second):
		}
	}
}

func processAlert(rdb *redis.Client, containerName, logLine, projectLabel, metadata string) {
	// Create a fingerprint of the error
	fingerprint := fmt.Sprintf("%x", sha256.Sum256([]byte(containerName+truncate(logLine, 40))))
	redisKey := fmt.Sprintf("watchdog:issue:%s", fingerprint)

	// Check Redis for existing issue ID
	issueID, err := rdb.Get(ctx, redisKey).Result()
	if err == nil {
		if !isIssueResolved(issueID) {
			return // Still open in Linear, skip
		}
	}

	// Create new issue
	newID := createLinearIssue(containerName, logLine, projectLabel, metadata)
	if newID != "" {
		rdb.Set(ctx, redisKey, newID, 0) // Cache indefinitely
		log.Printf("New Linear issue created for %s: %s", containerName, newID)
	}
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}

func isIssueResolved(issueID string) bool {
	gqlClient := graphql.NewClient("https://api.linear.app/graphql")
	req := graphql.NewRequest(`query($id: String!) { issue(id: $id) { state { type } } }`)
	req.Var("id", issueID)
	req.Header.Set("Authorization", linearAPIKey)

	var resp struct {
		Issue struct{ State struct{ Type string } }
	}
	if err := gqlClient.Run(ctx, req, &resp); err != nil {
		return true // Create new if API fails
	}
	t := resp.Issue.State.Type
	return t == "completed" || t == "canceled"
}

func createLinearIssue(name, logs, projectLabel, metadata string) string {
	gqlClient := graphql.NewClient("https://api.linear.app/graphql")
	projectID := strings.TrimSpace(projectLabel)
	description := fmt.Sprintf("Error detected in container **%s**:\n\n```\n%s\n```\n```%s\n```", name, logs, metadata)

	var req *graphql.Request
	if projectID != "" {
		req = graphql.NewRequest(`
			mutation($teamId: String!, $title: String!, $desc: String!, $projectId: String!) {
				issueCreate(input: { teamId: $teamId, title: $title, description: $desc, priority: 2, projectId: $projectId }) {
					success issue { id }
				}
			}
		`)
		req.Var("projectId", projectID)
	} else {
		req = graphql.NewRequest(`
			mutation($teamId: String!, $title: String!, $desc: String!) {
				issueCreate(input: { teamId: $teamId, title: $title, description: $desc, priority: 2 }) {
					success issue { id }
				}
			}
		`)
	}

	req.Var("teamId", linearTeamID)
	req.Var("title", fmt.Sprintf("[Log Alert] %s", name))
	req.Var("desc", description)
	req.Header.Set("Authorization", linearAPIKey)

	var resp struct {
		IssueCreate struct {
			Success bool
			Issue   struct{ Id string }
		}
	}
	if err := gqlClient.Run(ctx, req, &resp); err != nil {
		log.Println("Linear API Error:", err)
		return ""
	}
	return resp.IssueCreate.Issue.Id
}

func getExtendedMetadata(cli *client.Client, containerID string) map[string]string {
	// 1. Get Container Info (for compose labels)
	json, _ := cli.ContainerInspect(ctx, containerID)
	metadata := make(map[string]string)
	for k, v := range json.Config.Labels {
		// we need to filter for watchlog.* labels to avoid dumping everything into the issue description
		// and set the key as the suffix after watchlog. so it's easier to read in the issue description
		if after, ok := strings.CutPrefix(k, "watchlog."); ok {
			metadata[after] = v
		}
	}

	return metadata
}
