# Local, remote and EC2 access

AgentSec has two deployment modes. **Local** (the default) is reachable only from the machine that runs it. **Remote** is an explicit command that publishes the three learner ports so a browser on another machine can reach them.

> **`0.0.0.0` does not make a deployment safe for the public internet.** It only tells Docker to accept connections on every network interface. It opens no cloud firewall and adds **no authentication, no TLS and no learner isolation**. Remote mode is for one trusted learner on a restricted network path. Never expose these ports to `0.0.0.0/0`.

## How binding works

`AGENTSEC_BIND_ADDRESS` is the **host-side publish address** Docker uses for the three learner ports **8000** (Splunk Web and the Academy), **5001** (Attack Service) and **5000** (AcmeBank).

| Mode | `AGENTSEC_BIND_ADDRESS` | How you get it |
|------|------------------------|----------------|
| Local (default) | `127.0.0.1` | `./scripts/lab-up.sh`. The script forces this even if `.env` says otherwise, so a copied `.env` cannot expose a lab by accident. |
| Remote | `0.0.0.0` | `./scripts/lab-up.sh --remote` (the explicit operator choice). Running `docker compose` yourself honours the variable directly. |

This is **not** the application's own listener. Inside each container the Flask apps listen on `0.0.0.0` (`AGENTSEC_BIND_HOST`) because Docker reaches them over the private Compose network. That setting is unchanged and exposes nothing by itself: only a published host port does. Container-to-container traffic (Attack Service to AcmeBank, OTel, Splunk HEC) uses service names on the Compose network and is never affected by `AGENTSEC_BIND_ADDRESS`.

### What each mode publishes on the host

| Port | Service | Local | Remote |
|------|---------|-------|--------|
| 8000 | Splunk Web and AgentSec Academy | `127.0.0.1` | `0.0.0.0` |
| 5001 | Attack Service | `127.0.0.1` | `0.0.0.0` |
| 5000 | AcmeBank | `127.0.0.1` | `0.0.0.0` |
| 8088 | Splunk HEC | `127.0.0.1` | `127.0.0.1` |
| 4317, 4318 | OTel collector | `127.0.0.1` | `127.0.0.1` |
| 8089 | Splunk management | not published | not published |
| 11434 | Ollama | not published (the host Ollama listens on loopback) | not published |
| n/a | Docker socket, Loan Desk verifier, signing material, databases | never exposed | never exposed |

Only 8000, 5001 and 5000 ever change. `tests/security/test_remote_listener_bindings.py` renders the real Compose file in both modes and fails if any other port is published, or if 8089, 11434 or the Docker ports appear.

AcmeBank (5000) follows the same setting so an operator can reach its UI from the learner's browser. It is an unauthenticated teaching service with state-changing routes (see section F). Treat 5000 exactly like 5001: trusted learner addresses only, and leave its security-group rule out if the learner does not need the AcmeBank UI.

## A. Local laptop installation

```bash
cp .env.example .env            # never commit .env
./scripts/lab-preflight.sh
./scripts/lab-up.sh
python3 scripts/learner_ready.py
```

Open `http://127.0.0.1:8000/en-US/app/agentsec/ws_agentsec_home` on the same computer. Attack Service is `http://127.0.0.1:5001` and AcmeBank `http://127.0.0.1:5000`. These localhost URLs refer to the machine running the lab, which is correct for a local install. The first Splunk boot can take 10 to 20 minutes. You pull the model yourself; the lab never does (`docs/OPERATOR_SETUP_CHECKLIST.md`).

## B. EC2 (or any Linux VM) installation

1. **Instance.** Linux with Docker Engine and the Compose plugin; at least 8 GB of RAM for Docker (12 GB recommended, Splunk uses about 3 GB) and 15 GB of free disk. Use a dedicated instance.
2. **Security group, before you start.** Inbound rules, each from the learner's own address only (`/32` is one address). Example learner address `203.0.113.25`:

   | Type | Port | Source |
   |------|------|--------|
   | SSH | TCP 22 | the operator's address `/32` |
   | Custom TCP | 8000 | `203.0.113.25/32` |
   | Custom TCP | 5001 | `203.0.113.25/32` |
   | Custom TCP | 5000 | `203.0.113.25/32` (only if the learner needs the AcmeBank UI) |

   Do **not** add any rule for 8088, 4317, 4318, 8089 or 11434, and never use source `0.0.0.0/0` or `::/0` for any port here. Outbound can stay at the default.
3. **Install and start remote.**
   ```bash
   git clone <repository> && cd AgentSecLab
   cp .env.example .env
   echo 'AGENTSEC_PUBLIC_HOST=<public-ip-or-dns>' >> .env      # optional: scripts then print concrete URLs
   ./scripts/lab-preflight.sh --remote
   ./scripts/lab-up.sh --remote
   ./scripts/agentsec-access.sh
   ```
4. **Open from the learner's browser** with the instance's public IPv4 or public DNS name, **not** `127.0.0.1` or `localhost` (those would point at the learner's own computer):
   - Academy: `http://<public-ip-or-dns>:8000/en-US/app/agentsec/ws_agentsec_home`
   - Attack Service: `http://<public-ip-or-dns>:5001`
   - AcmeBank: `http://<public-ip-or-dns>:5000`

   An Elastic IP keeps the address stable across stop and start; without one the public IP changes and saved bookmarks break.
5. **Verify listeners on the server.** `ss -lnt` must show `0.0.0.0:8000`, `0.0.0.0:5001`, `0.0.0.0:5000`, `127.0.0.1:8088`, `127.0.0.1:4317`, `127.0.0.1:4318`, and nothing on 8089 or 11434. `python3 scripts/agentsec_access.py classify --mode remote` does the same check and exits non-zero on any leak.

`./scripts/agentsec-access.sh` prints the URLs again at any time. `AGENTSEC_PUBLIC_HOST` is read from the environment or `.env`. Remote mode may also read the public IPv4 from the link-local cloud metadata service (AWS IMDSv2, Azure, GCP). It never calls an external "what is my IP" site and prints a placeholder rather than invent an address.

**External reachability is NOT MEASURED by any script here.** `SERVICE READY` means the services answered on the server, not that your firewall let your laptop in. Test from the learner's machine.

## C. Switching between modes

**`lab-up.sh --remote` does not change a lab that is already running.** When Splunk is healthy, `lab-up.sh` starts the app services with `--no-recreate` and never recreates Splunk, so the published ports stay as they were. The readiness check then fails with `REMOTE LISTENERS: NOT ACCEPTED` (exit 2). To switch mode, **recreate the containers in place**:

```bash
export AGENTSEC_BIND_ADDRESS=0.0.0.0     # or 127.0.0.1 to go back to local
docker compose -f docker-compose.yml -f docker-compose.local.yml --profile local --env-file .env \
  up -d --force-recreate splunk acmebank attack_service
```

Recreating in place keeps every volume attached, including Splunk's configuration and indexed events (`splunk_etc`, `splunk_var`). Splunk is down for several minutes and its HEC input is re-initialised (`splunk_hec_init`).

**`./scripts/lab-down.sh` now only pauses the lab (`docker compose stop`) and removes nothing.** Removing containers is `--remove-containers` (`down`), which keeps named volumes and is **refused while Splunk is still on the legacy anonymous volumes**: for those, `down` followed by `up` starts Splunk with new empty volumes and orphans the old data (tested with a throwaway project). Deleting volumes is `--purge --yes-delete-all-lab-data`. The full table and the migration from anonymous to named volumes are in [ops/SPLUNK_VOLUME_MIGRATION.md](ops/SPLUNK_VOLUME_MIGRATION.md). On the pilot Mac, where the lab runs with read-only receipt mounts from a deploy override, do not switch mode between or during sessions; see `docs/PILOT_LAUNCH_CHECKLIST.md`.

## D. Links and redirects from a remote browser

Browser-visible URLs come from the address the browser used, never from `127.0.0.1`: Academy and Attack Service links, the Splunk Search hand-off, "Open in Splunk" and the AcmeBank links take the browser's hostname (client side) or the request `Host` (server side) and only change the port. Calls between containers use service names. `tests/security/test_remote_browser_urls.py` requests the Academy and lab pages as a remote host and fails if any rendered `href`, `src`, `action`, redirect or API payload contains `127.0.0.1`, `localhost` or `[::1]`. A local install still shows `http://127.0.0.1:8000/...`.

This was verified with a test client and a spoofed `Host`, and with a disposable container reached on the machine's LAN address. It was **not** verified from a separate physical machine.

## E. Firewall, TLS and authentication requirements

- **Cloud firewall:** restrict 8000, 5001 and 5000 to the learner's address (section B). This repository never changes a cloud firewall for you.
  Do not open 8000, 5001 or 5000 to `0.0.0.0/0`, and never open 8088, 4317, 4318, 8089 or 11434 to anyone.
- **Host firewall:** `ufw` or `firewalld` can still block a port the cloud firewall allowed. `lab-preflight.sh --remote` reports their status without changing anything, or prints `NOT MEASURED`. Add an allow rule for the learner address only. Do not disable the firewall.
- **TLS:** none of the learner ports use TLS. The Splunk login, predictions, run ids and every request travel as plaintext HTTP, readable and alterable by anyone on the network path. That is unacceptable over the open internet. For anything beyond a trusted private path, either use an SSH tunnel and keep the server in **local** mode, or put an authenticated HTTPS reverse proxy in front. The tunnel needs no inbound port beyond SSH:
  `ssh -L 8000:127.0.0.1:8000 -L 5001:127.0.0.1:5001 -L 5000:127.0.0.1:5000 user@server`, then open the `127.0.0.1` URLs on the learner's own machine. This repository does not configure a proxy.
- **Authentication:** Splunk Web (8000) requires a Splunk login. The Attack Service and AcmeBank have **no application authentication**: anyone who can reach 5001 or 5000 can launch runs and call their state-changing routes.
- **Credentials:** rotate the lab defaults in `.env` before any non-localhost bind, and never give learners the Splunk admin password.

## F. Security limits for externally reachable deployments

Remote mode supports **one trusted learner at a time**. It is **not** a secure concurrent multi-learner deployment. These are findings from reading the code, not from a multi-user test. None is fixed here.

| Area | Finding |
|------|---------|
| Authentication | None on Attack Service or AcmeBank (14 state-changing routes across the two apps and the Loan Desk mission). Splunk Web has its own login. |
| CSRF / origin checks | None found. A web page the learner visits could post to a reachable lab address. |
| Sessions | No learner identity on the server. Mission state lives in the browser (`sessionStorage` and `localStorage`). |
| Isolation | Run history and the Loan Desk run list are shared in memory across every client. One learner can see another's run ids. AcmeBank is one instance, not built for concurrent attacks. |
| Transport | Plain HTTP only. |
| Secrets | `FLASK_SECRET_KEY` is generated per process when unset. |
| Model | One Ollama instance serves one 3B model; concurrent use is untested. |

Do not describe a remote deployment as multi-learner ready until these are addressed and tested.

## G. Timing

`./scripts/lab-up.sh` prints four steps: prerequisites, bind plan, container start, readiness, and the elapsed time. The first Splunk boot can take 10 to 20 minutes. Image and model download time is UNKNOWN. See [QUICKSTART.md](QUICKSTART.md).
