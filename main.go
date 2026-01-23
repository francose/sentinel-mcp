package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strconv"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

const VERSION = "1.2.0"

// runSentinel executes the sentinel CLI with the given arguments
func runSentinel(args ...string) ([]byte, error) {
	cmd := exec.Command("sudo", append([]string{"sentinel"}, args...)...)
	return cmd.CombinedOutput()
}

// extractJSON extracts JSON object from output (handles sudo warnings)
func extractJSON(raw string) (string, error) {
	start := strings.Index(raw, "{")
	end := strings.LastIndex(raw, "}")

	if start == -1 || end == -1 || end < start {
		return "", fmt.Errorf("no valid JSON found in output")
	}

	return raw[start : end+1], nil
}

// isValidIP checks if a string is a valid IPv4 or IPv6 address
func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// errorResponse creates a structured error JSON response
func errorResponse(action, errMsg, errCode, fix string) string {
	resp := map[string]interface{}{
		"success":    false,
		"action":     action,
		"error":      errMsg,
		"error_code": errCode,
	}
	if fix != "" {
		resp["fix"] = fix
	}
	jsonBytes, _ := json.Marshal(resp)
	return string(jsonBytes)
}

func main() {
	// Initialize the MCP Server
	s := server.NewMCPServer(
		"sentinel-mcp",
		VERSION,
	)

	// ═══════════════════════════════════════════════════════════════════════════
	// Tool 1: get_system_health
	// ═══════════════════════════════════════════════════════════════════════════
	healthTool := mcp.NewTool("get_system_health",
		mcp.WithDescription("Get real-time system status including CPU load, temperature, memory, firewall status, and active network connections. Use this first to assess system state."),
	)

	s.AddTool(healthTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		output, err := runSentinel("--json")
		raw := string(output)

		if err != nil {
			return mcp.NewToolResultError(errorResponse(
				"get_system_health",
				fmt.Sprintf("Failed to get system health: %v", err),
				"EXECUTION_FAILED",
				"Ensure sentinel is installed and sudo is configured for passwordless access",
			)), nil
		}

		jsonPayload, err := extractJSON(raw)
		if err != nil {
			return mcp.NewToolResultError(errorResponse(
				"get_system_health",
				"Invalid JSON received from sentinel",
				"PARSE_ERROR",
				"Update sentinel to the latest version",
			)), nil
		}

		return mcp.NewToolResultText(jsonPayload), nil
	})

	// ═══════════════════════════════════════════════════════════════════════════
	// Tool 2: terminate_process
	// ═══════════════════════════════════════════════════════════════════════════
	terminateTool := mcp.NewTool("terminate_process",
		mcp.WithDescription("Kill a process by PID. Use SIGKILL for immediate termination. Requires sudo. Use when user wants to stop a specific process or when a runaway process is detected."),
		mcp.WithNumber("pid",
			mcp.Description("Process ID to terminate"),
			mcp.Required(),
		),
		mcp.WithString("reason",
			mcp.Description("Optional reason for audit logging"),
		),
	)

	s.AddTool(terminateTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		pid, err := request.RequireInt("pid")
		if err != nil {
			return mcp.NewToolResultError(errorResponse(
				"terminate_process",
				"Missing or invalid parameter: pid",
				"INVALID_PID",
				"Provide a valid numeric process ID",
			)), nil
		}

		if pid <= 0 {
			return mcp.NewToolResultError(errorResponse(
				"terminate_process",
				"PID must be a positive integer",
				"INVALID_PID",
				"Provide a valid process ID from get_system_health",
			)), nil
		}

		// Protected PIDs (kernel, launchd, etc.)
		if pid == 0 || pid == 1 {
			return mcp.NewToolResultError(errorResponse(
				"terminate_process",
				fmt.Sprintf("Cannot terminate protected system process (PID %d)", pid),
				"PROTECTED_PROCESS",
				"This process is essential for system operation",
			)), nil
		}

		output, err := runSentinel("--kill", strconv.Itoa(pid))
		raw := string(output)

		if err != nil {
			// Check for common error patterns
			if strings.Contains(raw, "No such process") || strings.Contains(raw, "ESRCH") {
				return mcp.NewToolResultText(errorResponse(
					"terminate_process",
					fmt.Sprintf("Process %d not found", pid),
					"PROCESS_NOT_FOUND",
					"The process may have already terminated",
				)), nil
			}
			if strings.Contains(raw, "Operation not permitted") || strings.Contains(raw, "EPERM") {
				return mcp.NewToolResultText(errorResponse(
					"terminate_process",
					fmt.Sprintf("Permission denied to kill process %d", pid),
					"PERMISSION_DENIED",
					fmt.Sprintf("Run sentinel with sudo: sudo sentinel --kill %d", pid),
				)), nil
			}
			return mcp.NewToolResultError(errorResponse(
				"terminate_process",
				fmt.Sprintf("Failed to terminate process: %v", err),
				"EXECUTION_FAILED",
				"Check if process exists and you have permissions",
			)), nil
		}

		// Try to extract JSON, otherwise return success
		if jsonPayload, err := extractJSON(raw); err == nil {
			return mcp.NewToolResultText(jsonPayload), nil
		}

		// Fallback success response
		resp := map[string]interface{}{
			"success": true,
			"action":  "terminate_process",
			"pid":     pid,
			"signal":  "SIGKILL",
			"details": strings.TrimSpace(raw),
		}
		jsonBytes, _ := json.Marshal(resp)
		return mcp.NewToolResultText(string(jsonBytes)), nil
	})

	// ═══════════════════════════════════════════════════════════════════════════
	// Tool 3: block_ip_address
	// ═══════════════════════════════════════════════════════════════════════════
	blockIPTool := mcp.NewTool("block_ip_address",
		mcp.WithDescription("Block an IP address in the macOS pf firewall. Blocks both inbound and outbound traffic. Use for malicious IPs or suspicious connections."),
		mcp.WithString("ip",
			mcp.Description("IP address to block (IPv4 or IPv6)"),
			mcp.Required(),
		),
		mcp.WithString("reason",
			mcp.Description("Why this IP is being blocked (for audit)"),
		),
	)

	s.AddTool(blockIPTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		ip, err := request.RequireString("ip")
		if err != nil {
			return mcp.NewToolResultError(errorResponse(
				"block_ip",
				"Missing required parameter: ip",
				"INVALID_IP",
				"Provide an IP address to block",
			)), nil
		}

		if !isValidIP(ip) {
			return mcp.NewToolResultError(errorResponse(
				"block_ip",
				"Invalid IP address format",
				"INVALID_IP",
				"Provide a valid IPv4 or IPv6 address",
			)), nil
		}

		output, err := runSentinel("--block-ip", ip)
		raw := string(output)

		if err != nil {
			if strings.Contains(raw, "already blocked") {
				return mcp.NewToolResultText(errorResponse(
					"block_ip",
					fmt.Sprintf("IP %s is already blocked", ip),
					"ALREADY_BLOCKED",
					"",
				)), nil
			}
			return mcp.NewToolResultError(errorResponse(
				"block_ip",
				fmt.Sprintf("Failed to block IP: %v", err),
				"EXECUTION_FAILED",
				"Ensure sentinel has pf firewall permissions",
			)), nil
		}

		if jsonPayload, err := extractJSON(raw); err == nil {
			return mcp.NewToolResultText(jsonPayload), nil
		}

		resp := map[string]interface{}{
			"success": true,
			"action":  "block_ip",
			"ip":      ip,
			"details": strings.TrimSpace(raw),
		}
		jsonBytes, _ := json.Marshal(resp)
		return mcp.NewToolResultText(string(jsonBytes)), nil
	})

	// ═══════════════════════════════════════════════════════════════════════════
	// Tool 4: unblock_ip_address
	// ═══════════════════════════════════════════════════════════════════════════
	unblockIPTool := mcp.NewTool("unblock_ip_address",
		mcp.WithDescription("Remove an IP from the firewall blocklist. Use when a blocked IP should be allowed again."),
		mcp.WithString("ip",
			mcp.Description("IP address to unblock"),
			mcp.Required(),
		),
	)

	s.AddTool(unblockIPTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		ip, err := request.RequireString("ip")
		if err != nil {
			return mcp.NewToolResultError(errorResponse(
				"unblock_ip",
				"Missing required parameter: ip",
				"INVALID_IP",
				"Provide an IP address to unblock",
			)), nil
		}

		if !isValidIP(ip) {
			return mcp.NewToolResultError(errorResponse(
				"unblock_ip",
				"Invalid IP address format",
				"INVALID_IP",
				"Provide a valid IPv4 or IPv6 address",
			)), nil
		}

		output, err := runSentinel("--unblock-ip", ip)
		raw := string(output)

		if err != nil {
			if strings.Contains(raw, "not blocked") || strings.Contains(raw, "not found") {
				return mcp.NewToolResultText(errorResponse(
					"unblock_ip",
					fmt.Sprintf("IP %s was not in the blocklist", ip),
					"NOT_BLOCKED",
					"",
				)), nil
			}
			return mcp.NewToolResultError(errorResponse(
				"unblock_ip",
				fmt.Sprintf("Failed to unblock IP: %v", err),
				"EXECUTION_FAILED",
				"Check if sentinel has pf firewall permissions",
			)), nil
		}

		if jsonPayload, err := extractJSON(raw); err == nil {
			return mcp.NewToolResultText(jsonPayload), nil
		}

		resp := map[string]interface{}{
			"success": true,
			"action":  "unblock_ip",
			"ip":      ip,
			"details": strings.TrimSpace(raw),
		}
		jsonBytes, _ := json.Marshal(resp)
		return mcp.NewToolResultText(string(jsonBytes)), nil
	})

	// ═══════════════════════════════════════════════════════════════════════════
	// Tool 5: list_blocked_ips
	// ═══════════════════════════════════════════════════════════════════════════
	listBlockedTool := mcp.NewTool("list_blocked_ips",
		mcp.WithDescription("List all IP addresses currently blocked by Sentinel. Use to show user what's blocked or before adding new blocks."),
	)

	s.AddTool(listBlockedTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// Note: This command may not need sudo
		cmd := exec.Command("sentinel", "--list-blocked")
		output, err := cmd.CombinedOutput()
		raw := string(output)

		if err != nil {
			// Try with sudo
			output, err = runSentinel("--list-blocked")
			raw = string(output)
			if err != nil {
				return mcp.NewToolResultError(errorResponse(
					"list_blocked",
					fmt.Sprintf("Failed to list blocked IPs: %v", err),
					"EXECUTION_FAILED",
					"Ensure sentinel supports --list-blocked flag",
				)), nil
			}
		}

		if jsonPayload, err := extractJSON(raw); err == nil {
			return mcp.NewToolResultText(jsonPayload), nil
		}

		// Parse plain text output into JSON
		lines := strings.Split(strings.TrimSpace(raw), "\n")
		var ips []string
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if isValidIP(line) {
				ips = append(ips, line)
			}
		}

		resp := map[string]interface{}{
			"success": true,
			"action":  "list_blocked",
			"ips":     ips,
		}
		jsonBytes, _ := json.Marshal(resp)
		return mcp.NewToolResultText(string(jsonBytes)), nil
	})

	// ═══════════════════════════════════════════════════════════════════════════
	// Tool 6: enable_firewall
	// ═══════════════════════════════════════════════════════════════════════════
	firewallTool := mcp.NewTool("enable_firewall",
		mcp.WithDescription("Enable the macOS Application Firewall if it's disabled. Use when security audit shows firewall is off."),
	)

	s.AddTool(firewallTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		output, err := runSentinel("-fix-firewall")
		raw := string(output)

		if err != nil {
			return mcp.NewToolResultError(errorResponse(
				"enable_firewall",
				fmt.Sprintf("Failed to enable firewall: %v", err),
				"EXECUTION_FAILED",
				"Ensure sudo is configured for passwordless sentinel access",
			)), nil
		}

		if jsonPayload, err := extractJSON(raw); err == nil {
			return mcp.NewToolResultText(jsonPayload), nil
		}

		resp := map[string]interface{}{
			"success": true,
			"action":  "enable_firewall",
			"details": strings.TrimSpace(raw),
		}
		jsonBytes, _ := json.Marshal(resp)
		return mcp.NewToolResultText(string(jsonBytes)), nil
	})

	// ═══════════════════════════════════════════════════════════════════════════
	// Tool 7: send_telemetry_webhook
	// ═══════════════════════════════════════════════════════════════════════════
	webhookTool := mcp.NewTool("send_telemetry_webhook",
		mcp.WithDescription("Send current system telemetry to a remote HTTP endpoint. Use for fleet monitoring or external logging."),
		mcp.WithString("url",
			mcp.Description("Webhook URL to send telemetry to"),
			mcp.Required(),
		),
	)

	s.AddTool(webhookTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		url, err := request.RequireString("url")
		if err != nil {
			return mcp.NewToolResultError(errorResponse(
				"webhook",
				"Missing required parameter: url",
				"INVALID_URL",
				"Provide a webhook URL",
			)), nil
		}

		if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			return mcp.NewToolResultError(errorResponse(
				"webhook",
				"Invalid URL format",
				"INVALID_URL",
				"Provide a valid HTTP or HTTPS URL",
			)), nil
		}

		output, err := runSentinel("--webhook", url)
		raw := string(output)

		if err != nil {
			return mcp.NewToolResultError(errorResponse(
				"webhook",
				fmt.Sprintf("Failed to send telemetry: %v", err),
				"WEBHOOK_FAILED",
				"Check if the URL is reachable and accepts POST requests",
			)), nil
		}

		if jsonPayload, err := extractJSON(raw); err == nil {
			return mcp.NewToolResultText(jsonPayload), nil
		}

		resp := map[string]interface{}{
			"success": true,
			"action":  "webhook",
			"target":  url,
			"details": strings.TrimSpace(raw),
		}
		jsonBytes, _ := json.Marshal(resp)
		return mcp.NewToolResultText(string(jsonBytes)), nil
	})

	// ═══════════════════════════════════════════════════════════════════════════
	// Tool 8: get_top_processes
	// ═══════════════════════════════════════════════════════════════════════════
	topProcessesTool := mcp.NewTool("get_top_processes",
		mcp.WithDescription("Get top CPU/memory consuming processes. Use when user asks what's using resources or system is slow."),
		mcp.WithNumber("count",
			mcp.Description("Number of processes to return (default: 10)"),
		),
	)

	s.AddTool(topProcessesTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		count := 10
		if c, err := request.RequireInt("count"); err == nil && c > 0 {
			count = c
		}

		output, err := runSentinel("--top", "--top-count", strconv.Itoa(count))
		raw := string(output)

		if err != nil {
			return mcp.NewToolResultError(errorResponse(
				"top_processes",
				fmt.Sprintf("Failed to get top processes: %v", err),
				"EXECUTION_FAILED",
				"Ensure sentinel supports --top flag",
			)), nil
		}

		if jsonPayload, err := extractJSON(raw); err == nil {
			return mcp.NewToolResultText(jsonPayload), nil
		}

		resp := map[string]interface{}{
			"success": true,
			"action":  "top_processes",
			"details": strings.TrimSpace(raw),
		}
		jsonBytes, _ := json.Marshal(resp)
		return mcp.NewToolResultText(string(jsonBytes)), nil
	})

	// ═══════════════════════════════════════════════════════════════════════════
	// Tool 9: restart_service
	// ═══════════════════════════════════════════════════════════════════════════
	restartServiceTool := mcp.NewTool("restart_service",
		mcp.WithDescription("Restart a system service (launchd on macOS, systemd on Linux). Use when a service needs to be restarted."),
		mcp.WithString("service",
			mcp.Description("Service label (macOS) or unit name (Linux)"),
			mcp.Required(),
		),
	)

	s.AddTool(restartServiceTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		service, err := request.RequireString("service")
		if err != nil {
			return mcp.NewToolResultError(errorResponse(
				"restart_service",
				"Missing required parameter: service",
				"INVALID_SERVICE",
				"Provide a service label to restart",
			)), nil
		}

		if strings.TrimSpace(service) == "" {
			return mcp.NewToolResultError(errorResponse(
				"restart_service",
				"Service name cannot be empty",
				"INVALID_SERVICE",
				"Provide a valid service label",
			)), nil
		}

		output, err := runSentinel("--restart-service", service)
		raw := string(output)

		if err != nil {
			if strings.Contains(raw, "not found") || strings.Contains(raw, "Could not find") {
				return mcp.NewToolResultText(errorResponse(
					"restart_service",
					fmt.Sprintf("Service '%s' not found", service),
					"SERVICE_NOT_FOUND",
					"Check the service name with launchctl list (macOS) or systemctl list-units (Linux)",
				)), nil
			}
			if strings.Contains(raw, "Operation not permitted") || strings.Contains(raw, "EPERM") {
				return mcp.NewToolResultText(errorResponse(
					"restart_service",
					fmt.Sprintf("Permission denied to restart service '%s'", service),
					"PERMISSION_DENIED",
					"Run with sudo permissions",
				)), nil
			}
			return mcp.NewToolResultError(errorResponse(
				"restart_service",
				fmt.Sprintf("Failed to restart service: %v", err),
				"RESTART_FAILED",
				"Check if the service exists and you have permissions",
			)), nil
		}

		if jsonPayload, err := extractJSON(raw); err == nil {
			return mcp.NewToolResultText(jsonPayload), nil
		}

		resp := map[string]interface{}{
			"success": true,
			"action":  "restart_service",
			"label":   service,
			"message": strings.TrimSpace(raw),
		}
		jsonBytes, _ := json.Marshal(resp)
		return mcp.NewToolResultText(string(jsonBytes)), nil
	})

	// ═══════════════════════════════════════════════════════════════════════════
	// Tool 10: check_updates
	// ═══════════════════════════════════════════════════════════════════════════
	checkUpdatesTool := mcp.NewTool("check_updates",
		mcp.WithDescription("Check for available OS updates. Use for security compliance or when user asks about updates."),
	)

	s.AddTool(checkUpdatesTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		cmd := exec.Command("sentinel", "--check-updates")
		output, err := cmd.CombinedOutput()
		raw := string(output)

		if err != nil {
			output, err = runSentinel("--check-updates")
			raw = string(output)
			if err != nil {
				return mcp.NewToolResultError(errorResponse(
					"check_updates",
					fmt.Sprintf("Failed to check updates: %v", err),
					"EXECUTION_FAILED",
					"Ensure sentinel supports --check-updates flag",
				)), nil
			}
		}

		if jsonPayload, err := extractJSON(raw); err == nil {
			return mcp.NewToolResultText(jsonPayload), nil
		}

		resp := map[string]interface{}{
			"success": true,
			"action":  "check_updates",
			"details": strings.TrimSpace(raw),
		}
		jsonBytes, _ := json.Marshal(resp)
		return mcp.NewToolResultText(string(jsonBytes)), nil
	})

	// ═══════════════════════════════════════════════════════════════════════════
	// Tool 11: scan_ports
	// ═══════════════════════════════════════════════════════════════════════════
	scanPortsTool := mcp.NewTool("scan_ports",
		mcp.WithDescription("Scan ports on a target host. Use for security audits or troubleshooting connectivity."),
		mcp.WithString("target",
			mcp.Description("Target host (e.g., localhost, 192.168.1.1)"),
			mcp.Required(),
		),
		mcp.WithString("port_range",
			mcp.Description("Ports to scan (e.g., '1-1024', '80,443,8080'). Default: 1-1024"),
		),
	)

	s.AddTool(scanPortsTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		target, err := request.RequireString("target")
		if err != nil {
			return mcp.NewToolResultError(errorResponse(
				"scan_ports",
				"Missing required parameter: target",
				"INVALID_TARGET",
				"Provide a target host to scan",
			)), nil
		}

		if strings.TrimSpace(target) == "" {
			return mcp.NewToolResultError(errorResponse(
				"scan_ports",
				"Target cannot be empty",
				"INVALID_TARGET",
				"Provide a valid hostname or IP address",
			)), nil
		}

		args := []string{"--scan-ports", target}
		if portRange, err := request.RequireString("port_range"); err == nil && portRange != "" {
			args = append(args, "--port-range", portRange)
		}

		cmd := exec.Command("sentinel", args...)
		output, err := cmd.CombinedOutput()
		raw := string(output)

		if err != nil {
			return mcp.NewToolResultError(errorResponse(
				"scan_ports",
				fmt.Sprintf("Failed to scan ports: %v", err),
				"SCAN_FAILED",
				"Check if target is reachable",
			)), nil
		}

		if jsonPayload, err := extractJSON(raw); err == nil {
			return mcp.NewToolResultText(jsonPayload), nil
		}

		resp := map[string]interface{}{
			"success": true,
			"action":  "scan_ports",
			"target":  target,
			"details": strings.TrimSpace(raw),
		}
		jsonBytes, _ := json.Marshal(resp)
		return mcp.NewToolResultText(string(jsonBytes)), nil
	})

	// ═══════════════════════════════════════════════════════════════════════════
	// Tool 12: get_asset_info
	// ═══════════════════════════════════════════════════════════════════════════
	assetInfoTool := mcp.NewTool("get_asset_info",
		mcp.WithDescription("Get complete system hardware/software inventory. Use when user asks about specs or for asset tracking."),
	)

	s.AddTool(assetInfoTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		cmd := exec.Command("sentinel", "--asset-info")
		output, err := cmd.CombinedOutput()
		raw := string(output)

		if err != nil {
			output, err = runSentinel("--asset-info")
			raw = string(output)
			if err != nil {
				return mcp.NewToolResultError(errorResponse(
					"asset_info",
					fmt.Sprintf("Failed to get asset info: %v", err),
					"EXECUTION_FAILED",
					"Ensure sentinel supports --asset-info flag",
				)), nil
			}
		}

		if jsonPayload, err := extractJSON(raw); err == nil {
			return mcp.NewToolResultText(jsonPayload), nil
		}

		resp := map[string]interface{}{
			"success": true,
			"action":  "asset_info",
			"details": strings.TrimSpace(raw),
		}
		jsonBytes, _ := json.Marshal(resp)
		return mcp.NewToolResultText(string(jsonBytes)), nil
	})

	// ═══════════════════════════════════════════════════════════════════════════
	// Tool 13: get_network_stats
	// ═══════════════════════════════════════════════════════════════════════════
	networkStatsTool := mcp.NewTool("get_network_stats",
		mcp.WithDescription("Get network interface statistics and connection counts. Use for bandwidth monitoring or network troubleshooting."),
	)

	s.AddTool(networkStatsTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		cmd := exec.Command("sentinel", "--network-stats")
		output, err := cmd.CombinedOutput()
		raw := string(output)

		if err != nil {
			output, err = runSentinel("--network-stats")
			raw = string(output)
			if err != nil {
				return mcp.NewToolResultError(errorResponse(
					"network_stats",
					fmt.Sprintf("Failed to get network stats: %v", err),
					"EXECUTION_FAILED",
					"Ensure sentinel supports --network-stats flag",
				)), nil
			}
		}

		if jsonPayload, err := extractJSON(raw); err == nil {
			return mcp.NewToolResultText(jsonPayload), nil
		}

		resp := map[string]interface{}{
			"success": true,
			"action":  "network_stats",
			"details": strings.TrimSpace(raw),
		}
		jsonBytes, _ := json.Marshal(resp)
		return mcp.NewToolResultText(string(jsonBytes)), nil
	})

	// ═══════════════════════════════════════════════════════════════════════════
	// Tool 14: security_audit
	// ═══════════════════════════════════════════════════════════════════════════
	securityAuditTool := mcp.NewTool("security_audit",
		mcp.WithDescription("Run a security posture assessment. Use when user asks 'Is my system secure?' or for compliance checks."),
	)

	s.AddTool(securityAuditTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		cmd := exec.Command("sentinel", "--security-audit")
		output, err := cmd.CombinedOutput()
		raw := string(output)

		if err != nil {
			output, err = runSentinel("--security-audit")
			raw = string(output)
			if err != nil {
				return mcp.NewToolResultError(errorResponse(
					"security_audit",
					fmt.Sprintf("Failed to run security audit: %v", err),
					"EXECUTION_FAILED",
					"Ensure sentinel supports --security-audit flag",
				)), nil
			}
		}

		if jsonPayload, err := extractJSON(raw); err == nil {
			return mcp.NewToolResultText(jsonPayload), nil
		}

		resp := map[string]interface{}{
			"success": true,
			"action":  "security_audit",
			"details": strings.TrimSpace(raw),
		}
		jsonBytes, _ := json.Marshal(resp)
		return mcp.NewToolResultText(string(jsonBytes)), nil
	})

	// ═══════════════════════════════════════════════════════════════════════════
	// Start Server
	// ═══════════════════════════════════════════════════════════════════════════
	if err := server.ServeStdio(s); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
