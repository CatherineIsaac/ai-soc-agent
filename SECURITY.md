# Security and Threat Model

This is a lab project. The response action (`block_ip`) is simulated and changes nothing on the host. This document describes the risks of giving an LLM agent security telemetry and response tools, what the current code does about each one, and what is planned.

## System and trust boundaries

| Component | Trust level | Notes |
|---|---|---|
| Suricata `eve.json` | **Untrusted data** | Contains fields derived from network traffic, which an attacker can influence |
| LLM | **Untrusted decision-maker** | Can be wrong and can be manipulated by its inputs |
| Tool code (`get_recent_alerts`, `block_ip`) | Trusted | Validates every argument it receives from the model |
| Human operator | Trusted | The only party that can approve a response action |
| OpenAI API | External processor | Receives the alert data the agent retrieves |

Core rule: **the model proposes, validated code executes, a human authorises.** The model must never hold unrestricted shell or root access and must never be able to approve its own actions.

## Threats

| # | Threat | Current state | Planned |
|---|---|---|---|
| 1 | **Prompt injection.** Text in the model's input instructs it to misuse tools or misreport findings. | The agent is instructed to treat alert contents as untrusted. This is a weak control. The real control is that the only action tool needs human approval and is simulated. | Field allow-listing; keep approval as the hard boundary. |
| 2 | **Malicious or untrusted telemetry.** Attacker-controlled fields (HTTP host, URL, user agent, DNS names, payload) reach the model. | Raw alert JSON is passed to the model. The lab rule is ICMP only, which carries no such fields, so this is untested. | Send only the fields needed; truncate and escape free-text values. |
| 3 | **Tool misuse.** The model calls a tool for the wrong target or the wrong reason. | Tools accept one validated IP address. The action tool is gated. | Policy checks before approval is even requested, for example refusing private, loopback and allow-listed addresses. |
| 4 | **Excessive agency.** The agent has more capability than the task needs. | Two tools, no shell, no file writes outside the audit log, no network actions. | Keep the tool set minimal as real actions are added. |
| 5 | **Arbitrary command execution.** Model output ends up in a shell. | Not possible in the current code. No tool builds or runs a command. | Real containment will use fixed command templates with validated arguments passed as an argument list, never a shell string. |
| 6 | **Privilege escalation.** A compromise of the agent yields elevated rights. | The agent runs as a normal user. Early runs used `sudo` unnecessarily; that has been corrected. | Privilege separation, described below. |
| 7 | **Unsafe argument construction.** A crafted argument such as `8.8.8.8; rm -rf /` or a CIDR range is passed through. | Arguments are parsed with Python's `ipaddress` module. Anything other than a single IPv4 or IPv6 address is rejected. Covered by unit tests. | Structured, typed arguments for every future tool. |
| 8 | **Secrets exposure.** API keys leak through the repository, logs or model context. | The key is in an untracked `.env` file with owner-only permissions. It is never placed in prompts or tool output. | A secrets manager if this leaves the lab. |
| 9 | **Authorization boundaries.** The component that decides is the same one that acts. | Read and act are separate tools, and only the act tool is gated. Everything still runs in one process under one user. | Separate processes and users for agent and executor. |
| 10 | **Human approval integrity.** Approval is bypassed, spoofed or given without understanding. | Approval is read from the terminal by the run loop, not exposed as a tool, and defaults to deny. The prompt shows tool and arguments but not the evidence. The operator is not authenticated. | Show evidence at the prompt; authenticate the approver; move approval out of the agent process. |
| 11 | **Audit logging.** Actions cannot be reconstructed afterwards. | Every approval decision is appended to a JSON Lines file with time, operator, tool, arguments and decision. The file is writable by the agent's own user and is not tamper-evident. | Logging by a separate component the agent cannot modify. |
| 12 | **Least privilege.** Components hold more access than they need. | The agent needs read access to one log file and nothing else. In the lab, that file is world-readable, which is more permissive than it should be. | Dedicated service user with group or ACL read access to the log only. |

## Planned privilege separation

This is a design, not something that exists in the code today.

```
unprivileged AI agent
  -> read-only access to security telemetry
  -> proposes a structured action (action name + validated arguments)
  -> human approval, outside the agent process
  -> narrow privileged executor
       - accepts a fixed set of actions only
       - re-validates every argument
       - fills a fixed command template, no shell interpretation
       - writes its own audit record
  -> controlled security action
```

The executor treats everything it receives from the agent as untrusted, including the claim that a human approved it.

## Out of scope

- Hardening of Suricata itself or the host operating system.
- The security of the OpenAI API and its handling of submitted data.
- Production deployment. This project has been tested against a single benign scenario.

## Reporting

This is a personal lab project. If you find a problem, please open a GitHub issue.
