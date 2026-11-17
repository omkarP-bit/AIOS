package main

import (
	"fmt"
	"os"
	"strings"

	"aios/internal/api"
	"aios/internal/catalog"
)

// commandGroups is the order groups are shown in `aios` and `aios-core help`.
var commandGroups = []string{
	"Observe (read-only)",
	"AI (proposal path)",
	"Protocol",
	"Cleanup (mutation)",
	"Audit and service",
}

// commandTable is the single description of the CLI surface. Help output and
// per-command usage both come from here so they cannot drift apart.
var commandTable = []commandInfo{
	{
		name: "status", group: "Observe (read-only)",
		usage:   "aios-core status [--json]",
		summary: "Host summary: kernel, uptime, load, processes, and cores.",
		examples: []string{
			"aios-core status",
			"aios-core status --json",
		},
	},
	{
		name: "cpu", group: "Observe (read-only)",
		usage:   "aios-core cpu [--interval SECONDS] [-w|--watch] [--json]",
		summary: "Sample CPU use over an interval.",
		examples: []string{
			"aios-core cpu",
			"aios-core cpu -w",
			"aios-core cpu --interval 1 --json",
		},
	},
	{
		name: "memory", group: "Observe (read-only)",
		usage:   "aios-core memory [-w|--watch] [--json]",
		summary: "Memory use and availability.",
		examples: []string{
			"aios-core memory",
			"aios-core memory -w",
		},
	},
	{
		name: "hostname", group: "Observe (read-only)",
		usage:   "aios-core hostname [--json]",
		summary: "Print the host name.",
		examples: []string{
			"aios-core hostname",
		},
	},
	{
		name: "processes", group: "Observe (read-only)",
		usage:   "aios-core processes [--limit N] [--sort cpu|memory|pid|name] [--name TEXT] [--json]",
		summary: "Process table, sorted and filterable.",
		examples: []string{
			"aios-core processes --limit 5 --sort memory",
			"aios-core processes --name ssh",
		},
	},
	{
		name: "inspect", group: "Observe (read-only)",
		usage:   "aios-core inspect PID [--json]",
		summary: "Inspect one process by PID.",
		examples: []string{
			"aios-core inspect 1",
		},
	},
	{
		name: "network", group: "Observe (read-only)",
		usage:   "aios-core network [--limit N] [--listening] [--json]",
		summary: "Socket table with an optional listening-only filter.",
		examples: []string{
			"aios-core network --listening",
		},
	},
	{
		name: "mounts", group: "Observe (read-only)",
		usage:   "aios-core mounts [--json]",
		summary: "Mounted filesystems and space use.",
		examples: []string{
			"aios-core mounts",
		},
	},
	{
		name: "ls", group: "Observe (read-only)",
		usage:   "aios-core ls PATH [--all] [--max N] [--json]",
		summary: "List a directory. Names and metadata only, never contents.",
		examples: []string{
			"aios-core ls ~/Downloads",
			"aios-core ls /var/log --all",
		},
	},
	{
		name: "ai", group: "AI (proposal path)",
		usage:   "aios-core ai QUESTION... [--execute] [--json] [--no-context]  (alias: ask)",
		summary: "Ask the local planner. It can only propose; the core decides.",
		examples: []string{
			`aios-core ai "how much memory is free?"`,
			`aios-core ai "list 5 processes" --execute`,
			`aios-core ai "check cpu" --json`,
		},
	},
	{
		name: "schema", group: "Protocol",
		usage:   "aios-core schema [--json]",
		summary: "List the allowed action ids.",
		examples: []string{
			"aios-core schema",
		},
	},
	{
		name: "validate", group: "Protocol",
		usage:   "aios-core validate [FILE|-] [--json]",
		summary: "Parse and validate a proposal locally, without the core.",
		examples: []string{
			"aios-core validate proposal.json",
			"cat proposal.json | aios-core validate",
		},
	},
	{
		name: "act", group: "Protocol",
		usage:   "aios-core act [FILE|-] [--dry-run] [--json]",
		summary: "Send a proposal to the core. --dry-run authorizes without running.",
		examples: []string{
			"aios-core act proposal.json --dry-run",
		},
	},
	{
		name: "cleanup", group: "Cleanup (mutation)",
		usage:   "aios-core cleanup scan|quarantine|restore ...",
		summary: "Reversible cleanup. Mutations require the exact plan hash.",
	},
	{
		name: "cleanup scan", group: "Cleanup (mutation)",
		usage:   "aios-core cleanup scan PATH [--plan-out FILE] [--min-age-days N] [--json]",
		summary: "Find cleanup candidates and write an approvable plan.",
		examples: []string{
			"aios-core cleanup scan ~/Downloads --plan-out plan.json",
		},
	},
	{
		name: "cleanup quarantine", group: "Cleanup (mutation)",
		usage:   "aios-core cleanup quarantine PLAN --confirm-plan-hash HASH [--json]",
		summary: "Move an approved plan's files into quarantine.",
		examples: []string{
			"aios-core cleanup quarantine plan.json --confirm-plan-hash sha256:...",
		},
	},
	{
		name: "cleanup restore", group: "Cleanup (mutation)",
		usage:   "aios-core cleanup restore PLAN --confirm-plan-hash HASH [--candidate ID] [--json]",
		summary: "Restore an approved plan from quarantine.",
		examples: []string{
			"aios-core cleanup restore plan.json --confirm-plan-hash sha256:...",
		},
	},
	{
		name: "ledger", group: "Audit and service",
		usage:   "aios-core ledger [--action ACTION] [--json]",
		summary: "Show the append-only audit trail.",
		examples: []string{
			"aios-core ledger",
			"aios-core ledger --action filesystem.quarantine",
		},
	},
	{
		name: "version", group: "Audit and service",
		usage:   "aios-core version [--json]",
		summary: "Print CLI, protocol, and catalog versions.",
		examples: []string{
			"aios-core version",
		},
	},
	{
		name: "serve", group: "Audit and service",
		usage:   "aios-core serve [--host H] [--port N]",
		summary: "Run the HTTP control API in the foreground.",
		examples: []string{
			"aios-core serve",
			"aios-core serve --port 9000",
		},
	},
}

type commandInfo struct {
	name     string
	group    string
	usage    string
	summary  string
	examples []string
}

func commandByName(name string) (commandInfo, bool) {
	for _, info := range commandTable {
		if info.name == name {
			return info, true
		}
	}
	return commandInfo{}, false
}

func usage() {
	fmt.Print(`aios — AIOS control CLI

The AI proposes. The core decides. The operator authorizes mutations.

Usage:
  aios <command> [options]
  aios-core help <command>

`)
	for _, group := range commandGroups {
		fmt.Println(group + ":")
		for _, info := range commandTable {
			if info.group != group {
				continue
			}
			fmt.Printf("  %-20s %s\n", info.name, info.summary)
		}
		fmt.Println()
	}
	fmt.Print(`Every data command accepts --json.
Run 'aios-core help <command>' for usage and examples.
`)
}

func helpCommand(args []string) int {
	if len(args) == 0 {
		usage()
		return 0
	}
	name := strings.Join(args, " ")
	info, ok := commandByName(name)
	if !ok {
		fmt.Fprintf(os.Stderr, "error: unknown command %q\n", name)
		if suggestion := suggestCommand(name); suggestion != "" {
			fmt.Fprintf(os.Stderr, "did you mean %q?\n", suggestion)
		}
		fmt.Fprintln(os.Stderr, "run 'aios-core help' to list commands")
		return 2
	}
	fmt.Printf("aios %s\n\n%s\n\nUsage:\n  %s\n", info.name, info.summary, info.usage)
	if len(info.examples) > 0 {
		fmt.Print("\nExamples:\n")
		for _, example := range info.examples {
			fmt.Printf("  %s\n", example)
		}
	}
	children := []commandInfo{}
	for _, child := range commandTable {
		if strings.HasPrefix(child.name, info.name+" ") {
			children = append(children, child)
		}
	}
	if len(children) > 0 {
		fmt.Print("\nCommands:\n")
		for _, child := range children {
			fmt.Printf("  %-20s %s\n", child.name, child.summary)
		}
	}
	if info.name != "cleanup" {
		fmt.Printf("\nFlags: aios %s --help\n", info.name)
	}
	return 0
}

func versionCommand(args []string) int {
	fs := newFlags("version")
	asJSON := jsonMode(fs)
	if err := parse(fs, args); err != nil {
		return parseCode(err)
	}
	payload := map[string]any{
		"version":          api.Version,
		"protocol_version": api.Version,
		"catalog_version":  catalog.CatalogVersion,
		"actions":          len(catalog.Catalog),
	}
	if *asJSON {
		printJSON(payload)
		return 0
	}
	fmt.Printf("aios       %s\n", api.Version)
	fmt.Printf("protocol   %s\n", api.Version)
	fmt.Printf("catalog    %s\n", catalog.CatalogVersion)
	fmt.Printf("actions    %d\n", len(catalog.Catalog))
	return 0
}

// suggestCommand returns the closest command name within two edits.
func suggestCommand(name string) string {
	best := ""
	bestDistance := 3
	for _, info := range commandTable {
		distance := editDistance(name, info.name)
		if distance < bestDistance {
			best, bestDistance = info.name, distance
		}
	}
	return best
}

func editDistance(a, b string) int {
	previous := make([]int, len(b)+1)
	current := make([]int, len(b)+1)
	for j := range previous {
		previous[j] = j
	}
	for i := 1; i <= len(a); i++ {
		current[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			current[j] = minInt(
				previous[j]+1,
				minInt(current[j-1]+1, previous[j-1]+cost),
			)
		}
		previous, current = current, previous
	}
	return previous[len(b)]
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
