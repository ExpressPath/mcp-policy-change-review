# Cedar sample inputs

These synthetic policies, entities, and fixtures are used by the included two-plane Cedar manifest at [`../multi-plane/mcp-multi-review-cedar.json`](../multi-plane/mcp-multi-review-cedar.json). The fixtures cover an allowed read and denials for an out-of-scope repository, inactive principal, destructive tool, and mismatched tool identity.

Install the official Cedar CLI, verify its release checksum, and run the multi-plane manifest from the Action package root:

```powershell
node .\bin\agent-policy-check.js mcp-multi-review `
  --manifest .\examples\multi-plane\mcp-multi-review-cedar.json `
  --require-policy-coverage `
  --fail-on-unexpected-new-allow `
  --fail-on-candidate-divergence `
  --format github
```

The example uses the same synthetic policy in both independently named planes. It demonstrates Cedar execution and shared scenario comparison; it is not customer policy or evidence of production behavior.
