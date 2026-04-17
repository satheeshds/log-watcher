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

	"github.com/docker/docker/api/types/container"
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

func main() {
	rdb := redis.NewClient(&redis.Options{Addr: redisAddr})
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Fatalf("Docker Client Error: %v", err)
	}

	log.Println("Watchlog started. Scanning containers...")

	// Listen for all containers on the host
	containers, err := cli.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		log.Fatal(err)
	}

	for _, c := range containers {
		cName := strings.TrimPrefix(c.Names[0], "/")

		// FILTERING LOGIC:
		// We only monitor if the label is explicitly set to true
		if c.Labels[monitorLabel] != "true" {
			log.Printf("Skipping %s (No monitor label found)", cName)
			continue
		}

		projectLabel := c.Labels[linearProjectLabel]
		if projectLabel != "" {
			log.Printf("Monitoring logs for: %s (Linear project ID: %s)", cName, projectLabel)
		} else {
			log.Printf("Monitoring logs for: %s", cName)
		}

		go tailLogs(cli, rdb, c.ID, cName, projectLabel)
	}

	select {} // Block forever
}

func tailLogs(cli *client.Client, rdb *redis.Client, containerID, name, projectLabel string) {
	options := container.LogsOptions{ShowStdout: true, ShowStderr: true, Follow: true, Tail: "0"}
	stream, err := cli.ContainerLogs(ctx, containerID, options)
	if err != nil {
		log.Printf("Error streaming logs for %s: %v", name, err)
		return
	}
	defer stream.Close()

	buf := make([]byte, 4096)
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
			break
		}
		if err != nil {
			return
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
	metadata := json.Config.Labels

	// 2. Get Image Info (for baked-in labels like commit hash)
	imageJSON, _, _ := cli.ImageInspectWithRaw(ctx, json.Image)

	// Merge image labels into our metadata map
	for k, v := range imageJSON.Config.Labels {
		if strings.HasPrefix(k, "watchlog.") {
			metadata[k] = v
		}
	}
	return metadata
}
