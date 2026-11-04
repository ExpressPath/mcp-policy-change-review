package agent_policy

import rego.v1

default decision := {
  "decision": "deny",
  "reason": "No regional rule grants this action.",
  "rule_id": "regional-default-deny",
}

decision := {
  "decision": "allow",
  "reason": "The scoped repository reader may read the approved repository.",
  "rule_id": "regional-allow-scoped-read",
} if {
  input.subject != null
  input.subject.status == "active"
  input.action.name == "read"
  input.context.tool == "mcp://workspace-code/read_file"
  input.resource.id == "repo:acme/api"
}

decision := {
  "decision": "allow",
  "reason": "Regression example: regional candidate mistakenly allows delete.",
  "rule_id": "regional-regression-allow-delete",
} if {
  input.action.name == "delete"
  input.context.tool == "mcp://workspace-code/delete_file"
}
