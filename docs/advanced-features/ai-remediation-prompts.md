# AI Remediation Prompts

The Security page can generate a copyable prompt for an AI coding CLI from current Trivy/Grype vulnerability scan results. This feature only copies text; it never runs commands, patches an image or changes a container.

## Usage

1. Enable the `security` HTTP API endpoint and scan the running containers.
2. Open **Security**, select **AI chooses safest fix**, **Source / Dockerfile fix**, or **Local NAS image rebuild**.
3. Use **Copy AI fix prompt** for all scanned containers with findings, or expand a container for its individual prompt.
4. Paste the prompt into an AI coding agent such as OpenCode, Claude Code or OpenHands. Ensure that the agent has the correct repository or NAS environment available, and review any proposed changes before approval.

Prompts include the container and image identifiers, scan timestamp, scanner name, and unresolved vulnerability IDs with severity, affected package, installed/fixed versions and advisory URLs. Findings classified as secrets or misconfigurations are intentionally excluded: secret values and host/container environment variables must never be forwarded to an AI CLI.

The agent is instructed to prefer maintained upstream images, verify package versions, retain Docker Compose and persistent-data configuration, rescan, test and provide rollback steps. A published fixed version is not proof that an in-place upgrade is safe or possible. Unsupported images may require rebuilding from source; findings without published fixes cannot always be patched.

**Security:** The generated text contains scanner metadata, which should be treated as untrusted input by the recipient AI. Only paste it into tools you trust. No automatic deployment is performed.
