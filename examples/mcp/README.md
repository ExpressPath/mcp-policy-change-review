# MCP tool surface snapshot example

The snapshot format wraps tools from one or more MCP servers. Give each server a stable, organization-defined server_id; server names are not unique identifiers, and tool names are only unique within a server. Preserve each complete tool definition in its tools array.

Compare the checked-in baseline with a newly reviewed inventory:

~~~powershell
node bin/agent-policy-check.js mcp-diff --baseline .\examples\mcp\baseline.json --candidate .\examples\mcp\candidate.json --fail-on-any-change --format github
~~~

The included candidate deliberately adds a deletion tool and changes an input schema. With --fail-on-any-change, the example exits with status 1 so a reviewer must inspect the inventory update. Remove the flag to report changes without failing the command.

To review inventory changes and authorization outcomes together, map MCP fixture metadata to the same server ID and tool name:

~~~powershell
node bin/agent-policy-check.js mcp-review `
  --baseline-snapshot .\examples\mcp\baseline.json `
  --candidate-snapshot .\examples\mcp\candidate.json `
  --baseline-policy .\policy\agent_policy.rego `
  --policy .\policy\agent_policy.rego `
  --fixtures .\examples\mcp\review-fixtures.json `
  --require-policy-coverage `
  --format github
~~~

The sample read schema change is linked to a scoped-read authorization case; the newly added delete tool is linked to a deny case. The command evaluates both baseline and candidate policies with OPA, then presents the related cases beside each inventory change. Replace the sample baseline policy with the target branch's policy when using the command in a pull-request workflow. `--require-policy-coverage` requires every mapped case to pass for each added or modified tool and an expected-and-actual deny for each removed tool.

The same snapshot pair also has a Cedar review example in [the Cedar guide](../cedar/README.md). Cedar fixtures must include both the mapping metadata and Cedar-specific request/entity inputs.

The comparator reads local JSON only. It does not connect to a server or execute a tool. Reports list server IDs, tool names, changed top-level fields, and SHA-256 fingerprints; they omit descriptions and schema contents. MCP annotations are included in the diff but are not treated as trusted authorization evidence.

Snapshot format:

~~~json
{
  "version": "1",
  "servers": [
    {
      "server_id": "github-prod",
      "tools": [
        {
          "name": "get_issue",
          "description": "Read an issue.",
          "inputSchema": { "type": "object", "properties": {} },
          "annotations": { "readOnlyHint": true }
        }
      ]
    }
  ]
}
~~~

Snapshot version versions this wrapper format. It is not the MCP protocol version. Keep server IDs stable between snapshots; changing an ID is reported as removing one server's tools and adding another server's tools. Store customer inventories in their own repository and review them under that repository's access controls.

For one server, the wrapper can be shorter:

~~~json
{
  "version": "1",
  "server_id": "github-prod",
  "tools": [
    {
      "name": "get_issue",
      "inputSchema": { "type": "object", "properties": {} }
    }
  ]
}
~~~
