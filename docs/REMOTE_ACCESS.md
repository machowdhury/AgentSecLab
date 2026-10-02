# Remote and cloud access

AgentSec has two deployment modes. The default stays on this computer. Remote mode is an explicit command for a Linux server or cloud VM.

Binding a port to `0.0.0.0` does not make the deployment safe. The host firewall and the cloud security group still decide who can connect. This repository does not change those firewalls and does not use cloud credentials.

## Where are you installing AgentSec?

### A. My laptop or desktop

```bash
./scripts/lab-preflight.sh
./scripts/lab-up.sh
```

Open the localhost URL the script prints:

http://127.0.0.1:8000/en-US/app/agentsec/ws_agentsec_home

### B. Remote Linux server, AWS EC2, Azure VM, or GCP VM

```bash
./scripts/lab-preflight.sh --remote
./scripts/lab-up.sh --remote
```

Open the server URL the script prints. To print it again later:

```bash
./scripts/agentsec-access.sh
```

Set `AGENTSEC_PUBLIC_HOST` in `.env` to your public IP or DNS name when you want a concrete URL. Remote mode may also read a public IPv4 address from the link-local cloud metadata service (AWS IMDSv2, Azure instance metadata, or GCP metadata). It does not call a public "what is my IP" website. If neither source works, the script prints `http://<your-server-public-ip>:8000/...` and does not invent an address.

External browser reachability is **NOT MEASURED**. `SERVICE READY` means the services answered on the server. It does not mean a firewall allowed your laptop.

## What remote mode publishes

| Port | Service | Remote mode |
|------|---------|-------------|
| 8000 | Splunk / AgentSec Academy | `0.0.0.0` |
| 5001 | Attack Service | `0.0.0.0` |
| 5000 | AcmeBank | stays `127.0.0.1` |
| 8088 | Splunk HEC | stays `127.0.0.1` |
| 4317, 4318 | OTel collector | stays `127.0.0.1` |
| 11434 | Ollama | not published |

Learners open Attack Service in a browser for LIVE launches, so port 5001 is a learner port. AcmeBank is reached by Attack Service over the Compose network. Learners do not need it in the browser.

`./scripts/lab-up.sh` without `--remote` forces `127.0.0.1` for ports 8000 and 5001 even if `.env` says otherwise.

Academy Search links, Attack Service links, and the inline investigation tables are paths on the Splunk host you already opened. Attack Service links in the Academy open `open_attack`, which sends the browser to port 5001 on the same hostname. The LIVE run.id box does not call `127.0.0.1`. A local install still looks like `http://127.0.0.1:8000/...`. A remote install looks like `http://SERVER-IP-OR-DNS:8000/...`. Do not put a temporary cloud address in these pages.

## Cloud firewall

Allow SSH and the learner ports only from the learner's current public IP. `/32` means that one address.

Example learner IP `99.232.130.106` (an example, not your address):

| Cloud | Where | Rules |
|-------|--------|--------|
| AWS | Security Group | TCP 22, TCP 8000, and TCP 5001 from `99.232.130.106/32` |
| Azure | Network security group | the same three rules from `99.232.130.106/32` |
| GCP | VPC firewall | allow `tcp:22`, `tcp:8000`, and `tcp:5001` from `99.232.130.106/32` |

Do not open these ports to the Internet:

- `8000` from `0.0.0.0/0`
- `5000` from `0.0.0.0/0`
- `5001` from `0.0.0.0/0`
- `8088` from `0.0.0.0/0`
- `11434` from `0.0.0.0/0`

Internet-wide exposure is unsupported. Do not expose the Attack Service to the Internet. This phase does not change a cloud firewall for you.

## Host firewall

Ubuntu `ufw`, `firewalld`, or another host firewall can block a port after the cloud firewall allows it. `./scripts/lab-preflight.sh --remote` reports `ufw` or `firewalld` when the command works without changing anything. If the status cannot be read, it prints `NOT MEASURED`.

Do not disable the host firewall to make the lab reachable. Add an allow rule for the learner IP only.

## Advanced patterns

A VPN, private VPC or VNet path, a bastion, or an authenticated HTTPS reverse proxy can sit in front of the lab. Those are separate deployments. They are not part of the beginner start, and this repository does not configure them.

## Timing

`./scripts/lab-up.sh` prints four steps that match the script: prerequisites, bind plan, container start, then readiness. It prints elapsed time when it finishes. The first Splunk boot can take 10–20 minutes. A measured clean-room was shorter. Image and model download time is **UNKNOWN**. See [QUICKSTART.md](QUICKSTART.md).
