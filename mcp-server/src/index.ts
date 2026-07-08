import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";

const BASE_URL = process.env.VENOM_API_URL ?? "http://localhost:8000";

async function apiCall(path: string, method = "GET", body?: unknown): Promise<unknown> {
  const res = await fetch(`${BASE_URL}${path}`, {
    method,
    headers: { "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  if (!res.ok) {
    throw new Error(`VENOM API error ${res.status}: ${text}`);
  }
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

const TOOLS: Tool[] = [
  {
    name: "start_scan",
    description:
      "Start a security vulnerability scan on a target URL using the VENOM AI platform. Returns a scan ID to track progress.",
    inputSchema: {
      type: "object",
      properties: {
        url: {
          type: "string",
          description: "Target URL to scan (e.g. https://example.com)",
        },
        scan_type: {
          type: "string",
          enum: ["full", "quick", "recon", "webapp", "infra"],
          description: "Type of scan. Defaults to 'full'.",
          default: "full",
        },
        user_id: {
          type: "string",
          description: "Optional user identifier for tracking",
          default: "mcp-claude",
        },
      },
      required: ["url"],
    },
  },
  {
    name: "get_scan_status",
    description:
      "Get the current status and results of a VENOM AI security scan by its scan ID.",
    inputSchema: {
      type: "object",
      properties: {
        scan_id: {
          type: "string",
          description: "The scan ID or Celery task ID returned from start_scan",
        },
      },
      required: ["scan_id"],
    },
  },
  {
    name: "list_scans",
    description: "List all security scans on the VENOM AI platform with their status and scores.",
    inputSchema: {
      type: "object",
      properties: {
        limit: {
          type: "number",
          description: "Max number of scans to return (default 20)",
          default: 20,
        },
      },
    },
  },
  {
    name: "get_vulnerabilities",
    description:
      "Get the detailed list of vulnerabilities found in a completed scan.",
    inputSchema: {
      type: "object",
      properties: {
        scan_id: {
          type: "string",
          description: "The scan ID to fetch vulnerabilities for",
        },
      },
      required: ["scan_id"],
    },
  },
  {
    name: "get_dashboard_stats",
    description:
      "Get overall VENOM AI platform statistics: total scans, vulnerability counts by severity, average security score, and threat trends.",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "list_reports",
    description: "List all completed scans that have generated security reports available for download.",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "get_report_url",
    description:
      "Get the download URL for a PDF security report for a completed scan.",
    inputSchema: {
      type: "object",
      properties: {
        scan_id: {
          type: "string",
          description: "The scan ID to get the report for",
        },
      },
      required: ["scan_id"],
    },
  },
  {
    name: "ask_venom",
    description:
      "Ask the VENOM AI cybersecurity chatbot a security question. Specializes in CVEs, exploits, malware analysis, penetration testing, and offensive/defensive security.",
    inputSchema: {
      type: "object",
      properties: {
        message: {
          type: "string",
          description: "Your cybersecurity question",
        },
        session_id: {
          type: "string",
          description: "Optional session ID to maintain conversation context",
        },
      },
      required: ["message"],
    },
  },
  {
    name: "health_check",
    description: "Check if the VENOM AI platform API is online and running.",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "virustotal_check",
    description:
      "Check a URL, IP address, domain, or file hash against VirusTotal threat intelligence. Auto-detects the input type.",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "URL (https://...), IP address, domain, MD5/SHA1/SHA256 hash",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "cve_lookup",
    description: "Look up a specific CVE by ID from the NIST NVD database. Returns CVSS score, description, affected products, and references.",
    inputSchema: {
      type: "object",
      properties: {
        cve_id: {
          type: "string",
          description: "CVE identifier e.g. CVE-2021-44228 (Log4Shell)",
        },
      },
      required: ["cve_id"],
    },
  },
  {
    name: "cve_search",
    description: "Search for CVEs by keyword (product name, vendor, vulnerability type) from the NIST NVD database.",
    inputSchema: {
      type: "object",
      properties: {
        keyword: {
          type: "string",
          description: "Search term e.g. 'apache log4j', 'wordpress', 'buffer overflow'",
        },
        limit: {
          type: "number",
          description: "Max results to return (default 10, max 20)",
          default: 10,
        },
      },
      required: ["keyword"],
    },
  },
  {
    name: "cve_recent",
    description: "Get the most recently published CVEs from NIST NVD, optionally filtered by severity.",
    inputSchema: {
      type: "object",
      properties: {
        limit: {
          type: "number",
          description: "Number of CVEs to return (default 10)",
          default: 10,
        },
        severity: {
          type: "string",
          enum: ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
          description: "Filter by CVSS severity level",
        },
      },
    },
  },
];

const server = new Server(
  { name: "venom-ai-mcp", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  const a = (args ?? {}) as Record<string, unknown>;

  try {
    let result: unknown;

    switch (name) {
      case "start_scan": {
        result = await apiCall("/api/scan/start", "POST", {
          url: a.url,
          scan_type: a.scan_type ?? "full",
          user_id: a.user_id ?? "mcp-claude",
        });
        break;
      }

      case "get_scan_status": {
        result = await apiCall(`/api/scan/results/${a.scan_id}`);
        break;
      }

      case "list_scans": {
        const limit = (a.limit as number) ?? 20;
        result = await apiCall(`/api/scan/list?limit=${limit}`);
        break;
      }

      case "get_vulnerabilities": {
        result = await apiCall(`/api/scan/vulnerabilities/${a.scan_id}`);
        break;
      }

      case "get_dashboard_stats": {
        result = await apiCall("/api/dashboard/stats");
        break;
      }

      case "list_reports": {
        result = await apiCall("/api/reports/");
        break;
      }

      case "get_report_url": {
        result = {
          scan_id: a.scan_id,
          report_url: `${BASE_URL}/api/reports/generate/${a.scan_id}`,
          message: `Download the PDF report at the URL above while the VENOM AI backend is running.`,
        };
        break;
      }

      case "ask_venom": {
        const chatRes = await apiCall("/api/chat/", "POST", {
          message: a.message,
          session_id: a.session_id ?? `mcp-${Date.now()}`,
        }) as Record<string, unknown>;
        result = chatRes;
        break;
      }

      case "health_check": {
        result = await apiCall("/api/health");
        break;
      }

      case "virustotal_check": {
        result = await apiCall("/api/threat/vt/check", "POST", { target: a.target });
        break;
      }

      case "cve_lookup": {
        result = await apiCall(`/api/threat/cve/${encodeURIComponent(a.cve_id as string)}`);
        break;
      }

      case "cve_search": {
        const limit = (a.limit as number) ?? 10;
        result = await apiCall(`/api/threat/cve/search?q=${encodeURIComponent(a.keyword as string)}&limit=${limit}`);
        break;
      }

      case "cve_recent": {
        const lim = (a.limit as number) ?? 10;
        const sev = a.severity ? `&severity=${a.severity}` : "";
        result = await apiCall(`/api/threat/cve/recent?limit=${lim}${sev}`);
        break;
      }

      default:
        throw new Error(`Unknown tool: ${name}`);
    }

    return {
      content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      content: [{ type: "text", text: `Error: ${message}` }],
      isError: true,
    };
  }
});

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  process.stderr.write("VENOM AI MCP server running. Connecting to: " + BASE_URL + "\n");
}

main().catch((err) => {
  process.stderr.write("Fatal: " + err + "\n");
  process.exit(1);
});
