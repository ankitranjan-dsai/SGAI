"""SecureGuard AI security tools, exposed as an MCP server.

The agents never touch the network or the filesystem directly. Every security
capability — CVE lookups, static analysis, source reads — is mediated by the
MCP server in this package, which enforces sandboxing and input validation.
"""
