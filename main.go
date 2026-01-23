package main

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func main() {
	// 1. Initialize the Server
	// "Sentinel-MCP" is the name the AI will see
	s := server.NewMCPServer(
		"Sentinel-MCP",
		"1.0.0",
	)

	// 2. Register the Tool
	// This tells Claude/LLM: "I have a tool called 'get_system_health'. Use it."
	healthTool := mcp.NewTool("get_system_health",
		mcp.WithDescription("Get CPU, Thermal, and Security telemetry from the local machine."),
	)

	// 3. Define the Function Logic
	s.AddTool(healthTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {

		// Run the main Sentinel binary in JSON mode
		// IMPORTANT: Ensure 'sentinel' is in your PATH or use absolute path
		cmd := exec.Command("sudo", "sentinel", "--json")
		output, err := cmd.CombinedOutput()

		raw := string(output)
		if err != nil {
			// Return error to AI so it knows something failed
			return mcp.NewToolResultError(fmt.Sprintf("Agent Error: %v\nOutput: %s", err, raw)), nil
		}

		// Cleanup: Extract JSON from output (in case sudo printed warnings)
		start := strings.Index(raw, "{")
		end := strings.LastIndex(raw, "}")

		if start == -1 || end == -1 {
			return mcp.NewToolResultError("Invalid JSON received from agent"), nil
		}

		jsonPayload := raw[start : end+1]

		// Return the JSON data as the tool result
		return mcp.NewToolResultText(jsonPayload), nil
	})

	// Tool 2: Enable Firewall (NEW!)
	fixTool := mcp.NewTool("enable_firewall",
		mcp.WithDescription("Enables the macOS Firewall. Use this IMMEDIATELY if telemetry shows 'Firewall Status: DISABLED'."),
	)

	s.AddTool(fixTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// We call the main binary with the new flag
		cmd := exec.Command("sudo", "sentinel", "-fix-firewall")
		output, err := cmd.CombinedOutput()

		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to enable firewall: %v", err)), nil
		}

		return mcp.NewToolResultText(string(output)), nil
	})

	// 4. Start Server on Stdio
	// This allows Claude Desktop to talk to it directly via the pipe
	fmt.Println("Starting Sentinel MCP Server...")
	if err := server.ServeStdio(s); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
