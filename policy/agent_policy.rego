package agent_policy

import rego.v1

default decision := {
  "decision": "deny",
  "reason": "No policy grants this action. Default deny applies.",
  "rule_id": "default-deny",
}

decision := {
  "decision": "deny",
  "reason": "Sensitive resources and bulk export are denied by a non-overridable policy.",
  "rule_id": "deny-sensitive",
} if {
  sensitive
}

decision := {
  "decision": "deny",
  "reason": "Unknown agent. The default policy denies requests without a registered identity.",
  "rule_id": "deny-unknown-agent",
} if {
  not sensitive
  input.subject == null
}

decision := {
  "decision": "deny",
  "reason": "This agent is revoked. Restore access through the owner's identity system.",
  "rule_id": "deny-revoked-agent",
} if {
  not sensitive
  input.subject != null
  input.subject.status != "active"
}

decision := {
  "decision": "deny",
  "reason": "The agent is not registered for the requested tool.",
  "rule_id": "deny-unregistered-tool",
} if {
  not sensitive
  input.subject != null
  input.subject.status == "active"
  not tool_allowed
}

decision := {
  "decision": "deny",
  "reason": "The requested resource is outside this agent's registered scope.",
  "rule_id": "deny-out-of-scope",
} if {
  not sensitive
  input.subject != null
  input.subject.status == "active"
  tool_allowed
  not in_scope
}

decision := {
  "decision": "allow",
  "reason": "Read-only action matches the agent, tool, and resource scope.",
  "rule_id": "allow-scoped-read",
} if {
  not sensitive
  input.subject != null
  input.subject.status == "active"
  tool_allowed
  in_scope
  input.action.name == "read"
}

decision := {
  "decision": "approval_required",
  "reason": "Mutating action is in scope but requires a human approval bound to this request.",
  "rule_id": "approve-mutations",
} if {
  not sensitive
  input.subject != null
  input.subject.status == "active"
  tool_allowed
  in_scope
  input.action.name in {"write", "delete", "deploy"}
}

sensitive if {
  input.action.name == "export"
}

sensitive if {
  regex.match(`(?i).*(secret|credential|private[-_]?key|api[-_]?key).*`, input.resource.id)
}

tool_allowed if {
  input.context.tool in input.subject.allowed_tools
}

in_scope if {
  some scope in input.subject.scopes
  scope == input.resource.id
}

in_scope if {
  some scope in input.subject.scopes
  endswith(scope, "*")
  prefix := substring(scope, 0, count(scope) - 1)
  startswith(input.resource.id, prefix)
}
