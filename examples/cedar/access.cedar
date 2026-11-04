@id("acme-repository-reader")
permit (
  principal,
  action == Action::"read",
  resource
)
when {
  principal.active == true &&
  principal.roles.contains("repo-reader") &&
  resource.organization == "acme" &&
  context.server_id == "mcp://workspace-code" &&
  context.tool_name == "read_file"
};
