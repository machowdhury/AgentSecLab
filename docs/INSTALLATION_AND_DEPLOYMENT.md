# Installation and deployment guide (RC2)

This guide installs AgentSecLab RC2 on a Linux host with Docker, using the installer (`./agentsec`). It is written from the three disposable-host acceptance runs of 2026-10-29 (records: clean host, final, final two checks). Every step is labelled:

| Label | Meaning |
|---|---|
| **TESTED** | Run on a real Ubuntu 24.04 host in an acceptance run, with the result shown |
| **NOT TESTED** | Written from the code or the Docker documentation; no run exists. Read it as a starting point, not a promise |

**Scope.** One learner, one machine, loopback only (the `localhost` deployment). Not multi-user and not for the public internet. The lab contains intentionally vulnerable agent profiles.

## 1. What you need

### Hardware and software
| Item | What the tested host had | What this means for you |
|---|---|---|
| CPU | 8 vCPU (Intel Xeon, AVX and AVX2) | Models run on the CPU; there is no GPU support |
| RAM | 31 GiB (8 vCPU `m6i.2xlarge`) | See the measurements below. **No minimum is claimed.** Plan generously |
| Disk | 120 GiB gp3 volume | The installer's preflight reported about 20 GB needed before the install |
| OS | Ubuntu 24.04 LTS, x86-64 | The only tested platform |
| Docker | Docker Engine 29.9.2, Compose 5.6.1 | Docker with Compose v2; the user must be in the `docker` group |
| Other | `git`, `python3`, `openssl`, `curl` | `python3` alone runs the installer (standard library) |
| Network | Internet access to pull images and models | About 16 GB of images and 3.3 GB of models on first install |

### Measured figures (one tested workload each, not requirements)
| Measurement | Value | Condition |
|---|---|---|
| Disk after install | **about 25 GiB** used of the 116 GiB volume | images 16.2 GB, volumes 5.7 GB of which 3.3 GB are models |
| Peak RAM | **about 6 GiB** (6,051 MiB used on the host) | during one Loan Desk transaction with both models loaded; Ollama 4.1 GiB of that; the sample covered about 28 s |
| Peak RAM, earlier | 3.5 GiB | four consecutive live attacks with only the 1b model |
| RAM at idle | 1.8 GiB | Splunk 0.7 GiB, Ollama 1.5 GiB with a model loaded |
| Clean install | **about 9 to 10 minutes** (9 min 32 s and 9 min 35 s in two runs) | on a fast data-centre network, including about 4 minutes while Splunk loads its sample data |
| `agentsec up` after a `down` | 67 s to start, 82 s until all services were healthy | models and data already present |
| `agentsec down` | 4 to 6 minutes | Splunk stops slowly (the installer gives it up to 120 s per container plus its own shutdown) |

These are single measurements on one machine. They are **not** minimum requirements, and your network, disk and CPU will change them.

### Platforms
| Platform | Status |
|---|---|
| Ubuntu 24.04 LTS x86-64, Docker Engine, localhost, gateway on port 443, generated test certificate | **TESTED** |
| Other Linux distributions, ARM Linux, rootless Docker, Podman | **NOT TESTED** |
| macOS (Docker Desktop) | **NOT TESTED** for RC2 (the older `scripts/lab-up.sh` flow, see [Local Docker lab](LOCAL_DOCKER_LAB.md), predates RC2 and is not covered here) |
| Windows (WSL2) | **NOT TESTED** |
| Gateway on port 8000 instead of 443 | **NOT TESTED** (configuration checked only) |
| Organization-managed certificate (`ORG_CERT`), non-loopback bind, `deployment: organization` | **NOT TESTED** |
| External Splunk Enterprise or Splunk Cloud | **NOT TESTED** against a real service (the client is tested against a local stand-in server and against the bundled Splunk) |

## 2. Install on Ubuntu 24.04

### 2.1 Prepare the host (the acceptance hosts used these commands; the acceptance logs are not published)
```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl git python3 openssl
curl -fsSL https://get.docker.com | sudo sh        # Docker's convenience script; or follow docs.docker.com for your policy
sudo usermod -aG docker "$USER"                   # then log out and back in so the group applies
docker --version && docker compose version
```
Expected: Docker 29.x and a Compose version line, with no `permission denied`. **Install and run everything as that unprivileged user, never with `sudo`.** The installer refuses `sudo` runs because the CTF secret and state must belong to you.

### 2.2 Get the code (NOT TESTED as written: the acceptance runs copied a `git bundle` of the commit)
```bash
git clone https://github.com/machowdhury/AgentSecLab.git
cd AgentSecLab
git log --oneline -1
```

### 2.3 Check the machine (TESTED)
```bash
./agentsec preflight
```
Expected lines (values vary): `OK DOCKER: Docker 29.9.2 with 8 CPUs and 30.8 GiB visible to containers`, `OK COMPOSE`, `OK DISK: ... free; about 20.3 GB needed`, `OK PORT_FREE: gateway: port 443 is free` (and the same for 8088, 4317 and 4318). Two `WARN` lines (the `llama3.2:1b` digest is not pinned yet, and the Ollama image tag floats) are normal in RC2. `ERROR` lines must be fixed first: see [section 11](#11-common-failures-and-exact-recovery).

### 2.4 Review the plan (TESTED; the acceptance logs are not published)
```bash
./agentsec --non-interactive --set gateway.ctf=true --accept-warnings all --dry-run plan
```
It prints what it would write and run and **starts nothing**. Expected: the services `ollama, acmebank, attack_service, otel_collector, splunk_app_init, splunk_hec_init, splunk, gateway`, `Ports: gateway 443`, four `Download on --apply` lines (the Splunk image, the Ollama image, `llama3.2:1b` and `llama3.2:latest`), and the commands it will run.

### 2.5 Install (TESTED)
```bash
./agentsec --non-interactive --set gateway.ctf=true --accept-warnings all --apply install
```
It writes `.env`, `.agentsec/compose.override.yml` and `.agentsec/install.json` (all owner-only), generates the gateway certificate and credentials, pulls the images and starts the stack. Expected: exit code 0 after about 9 to 10 minutes, with the last commands `docker compose pull ollama splunk` and `docker compose up -d ...`.

`gateway.ctf=true` also publishes the three CTF challenges through the gateway. Leave it off if you do not want them. To keep your choices in a file instead of repeating `--set`, write [`agentsec.install.json`](#9-configuration) (the installer reads it automatically).

### 2.6 Wait until everything is ready (TESTED)
```bash
./agentsec status
```
Expected, after the first Splunk start (a few more minutes after the install returns): every service `OK`, the two init jobs `exited (exit 0)`, and the last line `OK project 'agentsec': all services are up.` While Splunk is still loading, `attack_service` may show `NOT READY` for a minute: wait and run it again.

Check that both models are present (TESTED):
```bash
docker exec agentsec-ollama ollama list
```
Expected: `llama3.2:latest` (2.0 GB, ID `a80c4f17acd5`) and `llama3.2:1b` (1.3 GB, ID `baf6a787fdff`).

### 2.7 Open the Academy (TESTED through an SSH tunnel; the same requests run directly on the host were not run)
The gateway listens on `127.0.0.1:443` of the machine that runs the lab. On that machine:
```bash
cat .gateway/credentials.txt                     # two lines: learner=... and operator=...
curl --cacert .gateway/tls/ca.pem -s -o /dev/null -w '%{http_code}\n' https://localhost/learn/                     # 401: no credentials
curl --cacert .gateway/tls/ca.pem -s -o /dev/null -w '%{http_code}\n' -u "learner:<password>" https://localhost/learn/   # 200
```
In a browser go to `https://localhost/learn`. The browser will warn until it trusts the lab's certificate authority, `.gateway/tls/ca.pem` (a public certificate; its signing key was deleted). Import it as a trusted authority: Firefox, Settings, Privacy and Security, View Certificates, Authorities, Import; Chrome and Edge on Linux, Settings, Privacy and security, Manage certificates, Authorities, Import; macOS, add it in Keychain Access and set it to Always Trust. These browser steps are **NOT TESTED** (the runs used curl and a pinned-key test browser). Trust it only for this lab, on a machine you control. Then sign in as `learner`; you installed the lab, so the passwords are in `.gateway/credentials.txt`. Use `operator` to launch attacks (state-changing calls need the `operator` role). This one address is the whole learner path: ports 5000, 5001 and 8000 are internal, and learners investigate inside the Academy.

## 3. Install on AWS EC2

The acceptance runs used these settings (TESTED). They are what worked, not a sizing recommendation.

| Setting | Value used |
|---|---|
| Instance | `m6i.2xlarge` (8 vCPU, 32 GiB), an official Canonical Ubuntu 24.04 LTS x86-64 image |
| Storage | 120 GiB gp3 root volume, delete on termination |
| Network | Security group allowing only SSH (22) and HTTPS (443) from **your own public IP as a /32**. Nothing else; AcmeBank and Ollama publish no host port, and Splunk Web and HEC are published to the host's loopback only |
| Metadata | IMDSv2 required |
| Safety | A scheduled `shutdown -h` as an independent expiry, and `--instance-initiated-shutdown-behavior terminate` |
| Cost seen | about $0.43 per hour for the instance (AWS list price in `ca-central-1`, checked on the day), so a 36-minute run cost about $0.27 |

After the instance is up, follow sections 2.1 to 2.6 over SSH. The gateway listens on the instance's loopback, so reaching it from your laptop needs an SSH tunnel (section 5.3).

**Kernel warning for the bundled Splunk (important).** The current Ubuntu 24.04 AWS image ships Linux kernel 7.0. Splunk's bundled MongoDB refuses to start on Linux kernels **6.19 and newer**, which disables Splunk's KV store and with it Splunk authentication tokens (section 7.4). The lab itself still runs. If you need tokens, boot Ubuntu's own 6.8 kernel (TESTED on the acceptance host):
```bash
sudo apt-get install -y linux-image-6.8.0-1050-aws linux-modules-6.8.0-1050-aws
echo 'GRUB_DEFAULT="gnulinux-advanced-'"$(findmnt -no UUID /)"'>gnulinux-6.8.0-1050-aws-advanced-'"$(findmnt -no UUID /)"'"' | sudo tee /etc/default/grub.d/99-kernel-pin.cfg
sudo update-grub && sudo reboot
uname -r       # 6.8.0-1050-aws; the stack restarts by itself (restart: unless-stopped)
```
The commands are those used on the acceptance host (acceptance logs, not published). A reboot cancels any scheduled `shutdown`; schedule it again. Package versions change: check `apt-cache search '^linux-image-6.8.0-.*-aws$'` for the current 6.8 build.

## 4. Docker Compose and Ollama

The installer drives Docker Compose for you; you rarely run `docker compose` yourself. Compose files used: `docker-compose.yml`, `docker-compose.local.yml` (bundled Splunk), `docker-compose.gateway.yml`, `docker-compose.gateway-ctf.yml` (CTF), and the generated `.agentsec/compose.override.yml`. They are listed in `COMPOSE_FILE` in `.env`.

### The two Llama models (both required for the full lab)
| Model | Size | Used by | Why this one |
|---|---|---|---|
| `llama3.2:1b` (`OLLAMA_MODEL`, digest `baf6a787fdff`) | 1.3 GB | The AcmeBank pipeline labs that call a model (for example LAB-PI-001) | The validated default for the in-lab pipeline; small and fast |
| `llama3.2:latest` (`LOANDESK_MODEL`, the 3B build, digest `a80c4f17acd5`) | 2.0 GB | The Loan Desk mission (LAB-LOANDESK-001) | The Loan Desk drives a multi-step tool loop. Measured with the repository's loop benchmark (`scripts/bench_agent_loop.py`; results in final_acceptance2; small samples), `llama3.2:1b` completed **0 of 5** benign Loan Desk runs and `llama3.2:latest` completed **4 of 4**, so the Loan Desk does not reuse the 1b model |

With the **bundled** Ollama, the container's entrypoint pulls both when they are missing (TESTED: log lines `Pulling model ... Model ... pulled.` for each). The lab never swaps one model for another: if the configured model is not installed, the run is refused and the Academy shows the exact `ollama pull` command. The Ollama image (`ollama/ollama:latest`) is a floating tag, so the Ollama version can change between installs (0.40.13 was tested).

**Host Ollama** (`ollama.mode: host`, for example a native Ollama on the machine) is **NOT TESTED** on Linux; the installer then pulls nothing and lists no model download, so run `ollama pull llama3.2:1b` and `ollama pull llama3.2:latest` yourself. A **remote** Ollama is refused (`OLLAMA_REMOTE_UNSUPPORTED`).

If a pull fails with `x509: certificate signed by unknown authority`, fix certificate trust on the host or image (an organization proxy is the usual cause). Never disable certificate verification.

## 5. HTTPS gateway, certificates, authentication and tunnelling

### 5.1 What the gateway is (TESTED)
One nginx container is the only externally reachable application port. It terminates TLS, authenticates with HTTP basic authentication and routes: `/learn` (Academy), `/attack-service/` (the Attack UI and its launch API for the `operator` role), `/api/...` and, with `gateway.ctf`, the CTF routes.

**It does not put every service behind one address.** The real AcmeBank has no host port and is not routed (a read-only view is at `/attack-service/acmebank`). Splunk Web is not routed: it listens on `127.0.0.1:18000` only (use a tunnel). Ollama, HEC (`127.0.0.1:8088`) and the OpenTelemetry collector (`127.0.0.1:4317/4318`) are loopback-only. From outside the host, in the acceptance run, only SSH answered.

### 5.2 Certificates
- **Default (TESTED):** a generated 90-day test CA, name-constrained to the configured host name and `localhost`, with its signing key deleted. The server chain is `.gateway/tls/fullchain.pem`; the CA to trust is `.gateway/tls/ca.pem`. Verification passed with `Verify return code: 0 (ok)`; a request without the CA was refused.
- **Your own certificate (`ORG_CERT`):** an unencrypted key (mode 0400 or 0600), the full chain, and the host name in the certificate. **NOT TESTED.** No option disables verification.
- To inspect: `openssl s_client -connect localhost:443 -servername localhost -CAfile .gateway/tls/ca.pem </dev/null | grep 'Verify return code'`.

### 5.3 Authentication and remote access
Credentials are in `.gateway/credentials.txt` (mode 0600). Roles: `learner` can read the Academy and the CTF scoreboard; `operator` can also launch attacks and CTF attempts. This is **basic authentication, a stand-in rather than SSO, with no limit on failed logins** (a known limitation). Attacks are rate limited to 6 state-changing calls per minute (burst 5): scripted use gets `403` or `429` until it slows down.

Reaching a remote host needs an SSH tunnel, because the gateway only listens on the host's loopback:
```bash
# the variant used in the acceptance runs (TESTED: curl with the Host header; the test browser mapped localhost:443 to the tunnel and pinned the certificate key):
ssh -N -L 18443:127.0.0.1:443 ubuntu@<host>
curl --cacert ca.pem -H 'Host: localhost' -u learner:<password> https://localhost:18443/learn/
```
The gateway only accepts the host name it was configured for, **without a port**: a request whose `Host` header is `localhost:18443` receives `421 Misdirected Request`. For a normal browser the simplest way to satisfy this is to tunnel to local port 443 so the address is `https://localhost/learn` (this needs a privileged local port: `sudo ssh -N -L 443:127.0.0.1:443 ubuntu@<host>`, and root's SSH keys and agent may differ from yours) (**NOT TESTED** as written). Installing with `gateway.port=8000` and tunnelling `-L 8000:127.0.0.1:8000` is the other documented route and is also **NOT TESTED**. For Splunk Web: `ssh -N -L 18000:127.0.0.1:18000 ubuntu@<host>`, then `http://localhost:18000` (user `admin`, password `SPLUNK_PASSWORD` in `.env`).

## 6. Splunk

### 6.1 Bundled Splunk and HEC (TESTED)
The bundled Splunk Enterprise (10.2.7 in the acceptance run; the installer checks the image digest recorded in `deploy/images.lock.json`, while a bare `docker compose up` uses the `splunk/splunk:10.2` tag) runs in the `local` Compose profile. Telemetry flows from AcmeBank to the OpenTelemetry collector, which sends it to Splunk's HTTP Event Collector over TLS inside the Docker network (`https://agentsec_splunk:8088/...`, a generated token `SPLUNK_HEC_TOKEN`, index `agentsec_telemetry`, sourcetype `otel:agentic:json`). `scripts/hec-certs.sh` creates the HEC certificate on first install (`AGENTSEC_HEC_TLS_MODE=LOCAL_SELF_SIGNED`). The two init jobs create the index, the HEC input and the Splunk app and load the recorded sample runs.

Check that a live run arrived (TESTED, from the repository's acceptance record): launch a run in the Academy, copy its run id, and, as the operator, in Splunk Search (an optional Advanced view; learners use the Academy's Investigate notebook instead) run `index=agentsec_telemetry "agentsec.run.id"="<run id>" | stats count`. The count equals the run's local event count. Telemetry can take seconds to minutes to appear.

### 6.2 Evidence verification states
The Academy labels each live run with one of three words: **VERIFIED** (Splunk returned the run's events), **NOT VERIFIED** (Splunk answered and found nothing yet, or was not answering) and **VERIFICATION UNAVAILABLE** (the check could not run: no Splunk REST settings, a certificate that does not match, a refused token). **VERIFIED is optional and off by default**; without the settings in 6.3 a launch card reads VERIFICATION UNAVAILABLE, because the Attack Service has no Docker access.

**Search access for the Academy notebook (RC2).** The Investigate notebook and Security Assurance do not depend on VERIFIED. The installer provisions a least-privilege, search-only Splunk identity for them: run `./agentsec splunk-access` (check it with `./agentsec splunk-access --check`). The Attack Service then reaches Splunk's management API (`https://splunk:8089`) with strict TLS, reading the credential and CA from a read-only mount (`.splunk-access/`). Where it is not provisioned the notebook says so and fails closed; there is no silent fallback. The older host-side verifier that reads Docker is legacy, off by default (`AGENTSEC_LEGACY_HOST_VERIFIER=1` enables it) and ignored behind the gateway, so no installer deployment reports a Splunk-VERIFIED Loan Desk run by default. **Validated (RC2 acceptance run, 2026-10-30) on one real Splunk Enterprise 10.2.7 host with the bundled Splunk, the Ubuntu 24.04 and kernel 6.8 setup above; not validated against an external Splunk, Splunk Cloud or an organization-issued certificate.** Rotating the credential with `--force` does not revoke the previous token: see [Troubleshooting](TROUBLESHOOTING.md#rotating-the-search-credential-and-the-old-token).

### 6.3 Turning on REST verification (VERIFIED) for the bundled Splunk (TESTED once, on a disposable host)
VERIFIED needs all of the following, none of which the lab creates for you. The complete evidence is in [Splunk integration](SPLUNK_INTEGRATION.md).
1. A Splunk **management certificate** whose names include the host name the client uses (`splunk` and `agentsec_splunk` inside the Docker network), signed by a CA you give to the client. Splunk's default certificate has **no** subject alternative name, so strict verification fails with `Hostname mismatch, certificate is not valid for 'splunk'`. The certificate must allow **both server and client authentication** (the KV store uses it for mutual TLS) and Splunk must trust the CA (`[sslConfig] serverCert` and `sslRootCAPath` in `server.conf`). Do not trust Splunk's default `SplunkCommonCA`.
2. A **working KV store** (see 7.4), because Splunk keeps authentication tokens there.
3. A **search-only role** on `agentsec_telemetry`, a user with it, and an **authentication token** for that user, stored in a one-line file with mode 0600 that the container's user can read.
4. The installer settings that carry the above into the Attack Service container (TESTED):
```bash
./agentsec --non-interactive --set gateway.ctf=true \
  --set splunk.rest_url=https://splunk:8089 \
  --set splunk.ca_file=/home/ubuntu/splunk-pki/ca.pem \
  --set splunk.token_file=/home/ubuntu/splunk-rest/token \
  --accept-warnings all --apply install
docker exec -i agentsec-attack-service python - <<'PY'
import os
from agentsec import splunk_client as sc
for stage, state, detail in sc.client_for_mode(dict(os.environ)).diagnose(None): print(stage, state, detail)
PY
```
Expected: `connectivity PASS`, `authentication PASS`, `authorization PASS`, `search PASS`, then `telemetry NOT VERIFIED` until you pass a run id. A live run then reads **VERIFIED** (22 of 22 events in the tested run). Any other outcome is one of the three states above, never a silent success.

An organization's own Splunk Enterprise or Splunk Cloud uses the same client with `splunk.mode` set to `external_enterprise` or `cloud`; that is **NOT TESTED** against a real service.

### 6.4 Optional Splunk dashboards for AI Security Assurance (TESTED on a disposable host)

Security Assurance in the Academy (`/learn/assurance`: findings, raw evidence, an investigation notebook and a retest comparison) needs nothing from this section. The installer also deploys the `agentsec` Splunk app, which holds five dashboards and a finding page ([guide](AI_SECURITY_ASSURANCE.md)): an **optional advanced view** of the same findings, never a required step. In Splunk Web they are at `http://127.0.0.1:18000/en-US/app/agentsec/ws_assurance_executive` on the host, use Splunk's own login, and are **not routed through the gateway**: on a remote host reach them through an SSH tunnel (`ssh -L 18000:127.0.0.1:18000 <host>`). They need the same Linux kernel older than 6.19 as Splunk's database (section 7.1). Scanner and garak panels stay empty until their evidence packs are ingested.

## 7. Known issues, with the evidence to check

### 7.1 Splunk KV store fails on Linux 6.19 or newer (CONFIRMED on the test host)
Symptoms: Splunk is healthy and searches work, but `POST /services/authorization/tokens` answers `KVStore is not ready. Token auth system will not work.`

Diagnose (TESTED):
```bash
docker exec agentsec-splunk sh -c 'curl -sk -u "admin:$SPLUNK_PASSWORD" "https://localhost:8089/services/kvstore/status?output_mode=json"' | python3 -c 'import sys,json;print(json.load(sys.stdin)["entry"][0]["content"]["current"]["status"])'
docker exec -u root agentsec-splunk sh -c "grep -a 12257600 /opt/splunk/var/log/splunk/mongod.log | tail -1"
uname -r
```
Evidence from the tested host: status `failed`; `MongoDB cannot start: Linux kernel versions 6.19 and newer has a known incompatibility with this version of MongoDB (SERVER-121912)`; kernel `7.0.0-1014-aws`; the CPU had AVX, so it was not a CPU cause. Booting a 6.8 kernel (section 3) made the status `ready` with no Splunk change. Other causes show different log lines: read `mongod.log` and `splunkd.log` before changing anything.

### 7.2 After replacing the management certificate, the KV store fails again
Two causes were seen, both in the logs: Splunk did not trust the new CA (set `sslRootCAPath`), and `SSL peer certificate validation failed: unsuitable certificate purpose` (the certificate lacked the `clientAuth` extended key usage).

### 7.3 Other limits to expect
Splunk's REST VERIFIED path is not on by default (6.3). The host-side Loan Desk verifier is legacy: only the older `scripts/lab-up.sh` starts it, and it is ignored behind the gateway, so an installer deployment never shows a Splunk-VERIFIED Loan Desk run by default; the Investigate notebook (section 6.2) is the in-Academy way to read the run's rows. The CTF challenges are simulated. There is no login throttling.

## 8. Day-to-day operation (TESTED unless noted)
| Task | Command | Notes |
|---|---|---|
| Status | `./agentsec status` | read-only; exit code 5 when something is missing or not ready |
| Logs | `./agentsec logs [service] --tail 100` | known secrets are redacted (not when `--follow`) |
| Stop | `./agentsec down` | removes containers and the network; **keeps** volumes (Splunk data, models, telemetry) and `.gateway/` state |
| Start | `./agentsec up` | validates first; starts nothing if a check fails; 67 s in the test |
| Re-apply configuration | the same `install --apply` command | updates configuration only, never removes data (32 s in the test) |
| Restore previous generated files | `./agentsec rollback` | configuration only; touches no container or volume |

Persistence was verified across `down` and `up`: the CTF score and ledger, the Splunk events and the models survived. Never run `docker compose down -v`, `docker system prune` or `scripts/lab-down.sh --purge` unless you mean to delete the lab's data.

## 9. Configuration

### 9.1 Installer configuration (`agentsec.install.json` or `--set key=value`)
Unknown keys and wrong types are refused. `./agentsec print-config` shows the effective configuration (TESTED).

| Key | Default | Meaning |
|---|---|---|
| `project` | `agentsec` | Compose project and container prefix (`<project>-<service>`) |
| `naming` | `project` | `legacy` adopts an existing lab's fixed `agentsec_*` names |
| `deployment` | `localhost` | `localhost` or `organization` (behind your own gateway; needs `ack_external_controls`) |
| `gateway.enabled` / `host` / `port` / `bind` | `true` / `localhost` / `443` / `127.0.0.1` | the HTTPS gateway; ports 443 and 8000 are the supported values |
| `gateway.ctf` | `false` | publish the CTF through the gateway; the Attack Service then runs as you |
| `ollama.mode` | `bundled` | `bundled` or `host` (`remote` is refused) |
| `models.pipeline` / `models.loan_desk` | empty = lock default | `llama3.2:1b` and `llama3.2:latest`; a model outside `deploy/models.lock.json` needs `allow_unpinned_model` |
| `splunk.mode` | `bundled` | `bundled`, `external_enterprise`, `cloud` or `none` (replay only) |
| `splunk.rest_url` / `ca_file` / `token_file` / `index` | empty / empty / empty / `agentsec_telemetry` | REST verification (6.3); for the bundled Splunk both `rest_url` and `token_file` must be set |
| `ports.*` | splunk_web 8000, hec 8088, otel_grpc 4317, otel_http 4318, acmebank 5000, attack 5001 | host ports where they are published |
| `require_digests`, `allow_candidate_images`, `ack_splunk_upgrade`, `ack_recreate_existing` | `false` | safety switches described in [Installer](INSTALLER.md) |

Example file (TESTED with `print-config`):
```json
{
  "gateway": {"enabled": true, "host": "localhost", "port": 443, "ctf": true},
  "ollama": {"mode": "bundled"},
  "models": {"pipeline": "", "loan_desk": ""},
  "splunk": {"mode": "bundled"}
}
```
Do not edit the generated `.env` by hand: the installer detects it (`GENERATED_FILE_MODIFIED`) and refuses to start. Change the configuration and re-run the installer instead.

### 9.2 Generated environment variables (`.env`, mode 0600, never commit it)
| Variable | Purpose |
|---|---|
| `COMPOSE_PROJECT_NAME`, `COMPOSE_FILE`, `COMPOSE_PROFILES` | which Compose files and profiles make up the lab |
| `OLLAMA_MODEL`, `LOANDESK_MODEL`, `OLLAMA_BASE_URL` | models per role; the Ollama URL (host mode only) |
| `AGENTSEC_SECURITY_PROFILE`, `AGENTSEC_LAB_ID`, `AGENTSEC_TESTBED_MODE`, `AGENTSEC_OTEL_ENABLED` | lab behaviour; the default profile is `defended` and the launcher sets the profile per run |
| `AGENTSEC_BIND_ADDRESS` | publish address for the plain ports (loopback by default) |
| `SPLUNK_PASSWORD`, `SPLUNK_HEC_TOKEN`, `SPLUNK_IMAGE`, `SPLUNK_PLATFORM` | generated secrets (random per install) and the pinned image |
| `SPLUNK_HEC_ENDPOINT`, `SPLUNK_HEC_INDEX`, `SPLUNK_HEC_SOURCETYPE`, `SPLUNK_HEC_SOURCE`, `AGENTSEC_HEC_TLS_MODE` | telemetry path to Splunk |
| `AGENTSEC_PUBLIC_HOST`, `AGENTSEC_PUBLIC_PORT`, `AGENTSEC_GATEWAY_BIND`, `AGENTSEC_TLS_MODE`, `AGENTSEC_ATTACK_TIER` | the gateway |
| `AGENTSEC_SPLUNK_LOCAL_PORT` | where Splunk Web is published on loopback (18000) |
| `AGENTSEC_SPLUNK_MODE`, `AGENTSEC_SPLUNK_REST_URL`, `AGENTSEC_SPLUNK_CA_BUNDLE_FILE`, `AGENTSEC_SPLUNK_SEARCH_TOKEN_FILE`, `AGENTSEC_SPLUNK_INDEX` | REST verification (only when configured) |
| `AGENTSEC_CTF_GATEWAY`, `AGENTSEC_CTF_SECRET_FILE`, `AGENTSEC_CTF_STATE_HOST`, `AGENTSEC_CTF_UID`, `AGENTSEC_CTF_GID` | the CTF overlay (only with `gateway.ctf`) |

## 10. Upgrade, backup, recovery and uninstall

### Upgrade (partly tested)
```bash
git fetch && git checkout <new commit>      # review the change first
./agentsec preflight
./agentsec <your same options> --apply install     # TESTED: re-running over a running install updates configuration only
./agentsec status
```
Changing the Splunk image over existing data needs `ack_splunk_upgrade`; Splunk 10.6 is never allowed over existing data. Upgrading across RC2 builds beyond a re-run is **NOT TESTED**.

### Backup (NOT TESTED)
Stop the lab first so the files are consistent: `./agentsec down`. Then copy what is not reproducible: `.env`, `.gateway/` (credentials, TLS, CTF ledger and key), `.agentsec/`, `artifacts/`, and the Docker volumes `agentsec_splunk_etc`, `agentsec_splunk_var`, `agentsec_shared_telemetry`, `agentsec_splunk_app_agentsec` and (to avoid the re-download) `agentsec_ollama_models`. For a volume:
```bash
mkdir -p backup
docker run --rm -v agentsec_splunk_var:/v:ro -v "$PWD/backup":/b alpine tar czf /b/splunk_var.tgz -C /v .
```
Restoring is the reverse into empty volumes before the first `up`. The CTF ledger rolls back silently if you restore an older consistent pair of `ledger.jsonl` and `ledger.head`, or delete both.

### Recovery
- **A failed `up`** removes and rolls back nothing. Repeat it, or run `./agentsec down` and `./agentsec up`.
- **A damaged configuration:** `./agentsec rollback` restores the previous generated files (TESTED in the installer's own test suite, not on a host).
- **Splunk will not start after a crash:** read `./agentsec logs splunk --tail 200`; do not delete volumes as a first step.

### Uninstall (NOT TESTED)
```bash
./agentsec down
docker volume ls --filter name=agentsec_          # review the list, then remove only these:
docker volume rm agentsec_splunk_etc agentsec_splunk_var agentsec_shared_telemetry agentsec_splunk_app_agentsec agentsec_ollama_models
docker image ls | grep -E 'splunk/splunk|ollama/ollama|otel/opentelemetry|nginx'
cd .. && rm -rf AgentSecLab                      # removes .env, .gateway (credentials, CA, CTF state) and artifacts
```
Check the names with `docker volume ls` first; this removes your Splunk data and models.

## 11. Common failures and exact recovery

| Symptom | Cause and recovery |
|---|---|
| `permission denied` talking to the Docker daemon | You are not in the `docker` group: `sudo usermod -aG docker "$USER"`, log out and in, retry. Do not use `sudo ./agentsec` |
| `ERROR PORT_IN_USE: ... port 443 ... already in use` | Another process holds the port: stop it, or install with `--set gateway.port=8000` (**NOT TESTED**). Ports 4317, 4318 and 8088 are also checked |
| `ERROR GENERATED_FILE_MODIFIED: .env changed since it was generated` | You edited `.env`. Put the change in `agentsec.install.json` (or `--set`) and re-run `install --apply`. If you must replace a foreign `.env`: `--force-env` keeps a backup |
| `./agentsec status` says `NOT READY` for Splunk or `attack_service` | The first Splunk start loads data for several minutes. Wait, then re-run `status`. If it stays unhealthy: `./agentsec logs splunk --tail 200` |
| Browser or curl: `421 Misdirected Request` | The `Host` header carries a port. Use `https://localhost/learn` (port 443), not `https://localhost:8443` (section 5.3) |
| Browser warns about the certificate | Trust `.gateway/tls/ca.pem` for this host name. Do not click through a warning on a shared machine |
| `401 Unauthorized` | Wrong credentials: read `.gateway/credentials.txt` |
| `403` on a launch or a CTF start | You are signed in as `learner`: sign in as `operator`. A `403` or `429` after many rapid calls is the 6 per minute limit: wait a minute |
| Launch card: runtime unreachable | AcmeBank or the Attack Service is not ready: `./agentsec status`. Nothing was launched; try again |
| Academy: Loan Desk model not installed | `docker exec agentsec-ollama ollama pull llama3.2:latest` (bundled Ollama). The status page then shows the model and its digest |
| `WAITING_FOR_EVIDENCE` | The honest default: telemetry arrives seconds to minutes later. It is not a failed attack and not proof of prevention. Check again, or search Splunk with the starter search |
| `VERIFICATION UNAVAILABLE` | The REST check is not configured or cannot run (6.2, 6.3). Search Splunk yourself |
| `Hostname mismatch, certificate is not valid for 'splunk'` | Splunk's default management certificate has no host name (6.3, 7.2) |
| `KVStore is not ready. Token auth system will not work.` | Splunk's KV store did not start: diagnose with 7.1 |
| `Pulling` a model fails with `x509` | A TLS inspection proxy: fix certificate trust on the host (section 4); never disable verification |
| CTF returns `ledger_integrity_failed` or a zero scoreboard | The CTF state in `.gateway/ctf-state` was damaged or rolled back; see [CTF](CTF.md) for repair or reset |
| Out of disk | Images 16 GB and volumes 6 GB after the install; check `docker system df`. Do not `prune` blindly |
