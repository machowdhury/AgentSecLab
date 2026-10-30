# Install AgentSecLab

Pick the one that matches you. Each path is a single sequence; you do not need to understand the architecture first.

| I want to run the lab… | Go to |
|---|---|
| **on this computer** and open it in this computer's browser | [LOCAL](#local-install-on-your-own-ubuntu-computer) |
| **on a remote Ubuntu server or cloud VM** and open it directly from my laptop | [REMOTE](#remote-ubuntu-server-or-cloud-vm-open-it-directly-from-your-laptop) |

**Where this has been verified.** Ubuntu 24.04 LTS on x86-64 with Docker Engine, on a cloud VM (8 vCPU, 32 GiB RAM, 120 GiB disk). That is the only platform the install has been run on, end to end.

| Platform | Status |
|---|---|
| Ubuntu 24.04 x86-64, Docker Engine | **Verified** |
| macOS (Docker Desktop), Windows, other Linux, ARM, Podman, rootless Docker | **Not verified.** The installer's read-only checks start on a Mac and tell you what they find, but a full install has not been run there. Try it only if you accept that |
| REMOTE: direct HTTPS to a DNS name on port 443, security-group restricted (no tunnel) | **Verified** on one Ubuntu 24.04 cloud VM: certificate and host-name checks, 401/200/403, blocked from a non-allowed source, only the gateway port open, notebook and Security Assurance on real Splunk data |
| REMOTE variants: another port (8000), a bare IP address instead of a name (not supported), the CA trusted in the operating system's certificate store (the test browser pinned the server key instead) | **Not validated** |

The lab is for one learner on one machine and contains intentionally vulnerable agent profiles. Never expose it to the open internet. Measured disk, memory and timings are in the [installer reference](INSTALLER.md#requirements-measurements-and-platform-status); none of them is a minimum requirement.

---

## LOCAL: install on your own Ubuntu computer

**You need:** Ubuntu 24.04 (x86-64), about 25 GiB of free disk and a good internet connection (about 16 GB of images and 3.3 GB of models are downloaded), `sudo` rights to install Docker, and these ports free on the machine: 443, 8088, 4317, 4318.

**1. Install the tools** (skip what you already have):
```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl git python3 openssl
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker "$USER"        # then log out and back in
docker --version && docker compose version
```
Run everything below as your normal user, **never with `sudo`**; the installer refuses it.

**2. Get the code and check the machine:**
```bash
git clone https://github.com/machowdhury/AgentSecLab.git
cd AgentSecLab
./agentsec preflight
```
Two `WARN` lines (an unpinned model digest and a floating image tag) are normal. Fix any `ERROR` line before going on; most are a port already in use or Docker not running.

**3. Install** (about 10 minutes; it downloads and starts everything):
```bash
./agentsec --non-interactive --set gateway.ctf=true --accept-warnings all --apply install
./agentsec status
```
`gateway.ctf=true` also turns on the three CTF challenges. `status` should end with `OK project 'agentsec': all services are up.` Splunk takes a few more minutes to load after the install returns; if a service shows `NOT READY`, wait a minute and run `status` again.

**4. Trust the lab's certificate, then open the Academy.** The lab serves HTTPS with its own certificate authority, so a browser warns until you trust it. The file is `.gateway/tls/ca.pem`. It is a public certificate that can only vouch for `localhost` and the lab's host name, and its signing key was deleted. Import it as a trusted authority:
- **Chrome or Edge:** Settings, Privacy and security, Manage certificates, Authorities, Import.
- **Firefox:** Settings, Privacy and Security, View Certificates, Authorities, Import (tick "Trust this CA to identify websites").

Browser menus change between versions and these steps have not been run in every browser. To check the certificate without a browser:
```bash
curl --cacert .gateway/tls/ca.pem -s -o /dev/null -w '%{http_code}\n' https://localhost/learn/      # 401 = secure and asking for a password
```
Do not click through a certificate warning on a shared machine.

Then open **https://localhost/learn** and sign in. The passwords are in `.gateway/credentials.txt`: use `operator` (it can launch attacks) for the workshops, `learner` for read-only.

**Stop and restart** (your data, models and Splunk history are kept):
| Task | Command |
|---|---|
| Stop the lab | `./agentsec down` (can take a few minutes while Splunk shuts down) |
| Start it again | `./agentsec up`, then `./agentsec status` (about 1 to 2 minutes) |
| Check it | `./agentsec status` |

Never run `docker compose down -v` or `docker system prune` unless you mean to erase the lab's data.

---

## REMOTE: Ubuntu server or cloud VM, open it directly from your laptop

The lab runs on the server and you open `https://<hostname>/learn` in your laptop's browser. No SSH tunnel is needed. Only the lab's HTTPS gateway port is published to the network. Splunk, HEC, Ollama, the OpenTelemetry collector, AcmeBank and the Attack Service stay on the server's loopback or are not published at all.

**This makes an intentionally vulnerable lab reachable over the network, with a basic password login that has no failed-login limit. You must restrict who can connect.** Allow the HTTPS port only from your own IP address (or a VPN range) in the cloud security group or firewall. Never allow `0.0.0.0/0`. Docker publishes ports around `ufw`, so a `ufw` rule alone is not enough; use the cloud security group, or Docker's `DOCKER-USER` rules.

**You need:**
- *Server:* Ubuntu 24.04 x86-64 (tested at 8 vCPU, 32 GiB RAM, 120 GiB disk) with `sudo`, internet access and SSH. If `uname -r` starts with 6.19 or higher (the current Ubuntu AWS image ships 7.0), read the [kernel note](SPLUNK_INTEGRATION.md#kernel-619-or-newer-and-the-bundled-splunk) first.
- *A DNS name for the server*, such as `lab.example.com`, pointing at the server's IP address. It must be a name, **not a bare IP address**: the lab's certificate is issued for the name. (For a quick test without your own DNS, a name like `203-0-113-10.sslip.io` resolves to `203.0.113.10`.)
- *Firewall:* inbound SSH (22) from your administrative IP and inbound HTTPS (443) from your own IP only. Nothing else.
- *Laptop:* a browser and `scp`.

**On the server** (`ssh <user>@<server>`):

**1. Install the tools.** Run step 1 of the LOCAL path, log out and back in, then:
```bash
git clone https://github.com/machowdhury/AgentSecLab.git
cd AgentSecLab
./agentsec preflight
```
**2. Install** (about 10 minutes; replace the host name with yours):
```bash
./agentsec --non-interactive --ack-external-controls --accept-warnings all \
  --set deployment=organization --set gateway.bind=0.0.0.0 \
  --set gateway.host=lab.example.com --set gateway.ctf=true --apply install
./agentsec status
```
What the extra settings mean:
- `gateway.host` is the name in your browser's address bar. The gateway refuses any other name (`421`), and the generated certificate covers only this name and `localhost`.
- `gateway.bind=0.0.0.0` publishes the gateway's one HTTPS port on the server's network interface. It does not publish any other service.
- `deployment=organization` with `--ack-external-controls` is the installer's required confirmation that **you** restrict network access (the firewall step above), because the lab's own login is not meant to face an untrusted network. The installer prints a warning that the gateway listens on every interface; `--accept-warnings all` accepts it.

**On your laptop:**

**3. Copy the certificate and read the passwords:**
```bash
scp <user>@<server>:AgentSecLab/.gateway/tls/ca.pem ./agentseclab-ca.pem
ssh <user>@<server> cat AgentSecLab/.gateway/credentials.txt
```
**4. Trust the certificate.** The lab signs its own certificate, so import `agentseclab-ca.pem` as a trusted authority with the browser steps from LOCAL step 4 (on macOS, double-click it, add it to Keychain Access, and set Trust to "Always Trust"). It can only vouch for your lab's host name and `localhost`. To check it without a browser:
```bash
curl --cacert agentseclab-ca.pem -s -o /dev/null -w '%{http_code}\n' https://lab.example.com/learn/    # 401 = verified TLS, password required
```
**5. Open `https://lab.example.com/learn`** and sign in as `operator` (launch attacks) or `learner` (read-only). Another port (`--set gateway.port=8000`, address `https://lab.example.com:8000/learn`) is available but was not run on a real host.

**Stop and restart:**
| Task | Command (on the server) |
|---|---|
| Stop the lab | `./agentsec down` (data is kept; a few minutes) |
| Start the lab | `./agentsec up`, then `./agentsec status` |

After a server reboot the lab restarts by itself. If the server's name changes, the certificate no longer matches; move `.gateway` aside and install again with the new name (not tested). A cloud VM that is stopped but not deleted still costs for its disk: delete it when you are done.

---

## If something goes wrong

| You see | Do this |
|---|---|
| `permission denied` talking to Docker | Log out and back in after `usermod`; do not use `sudo ./agentsec` |
| `ERROR PORT_IN_USE` | Stop whatever uses that port, then run `preflight` again |
| `NOT READY` right after install | Splunk is still loading: wait a minute, run `./agentsec status` again |
| Browser certificate warning | Import the lab's CA (step 4); do not click through |
| REMOTE: the page does not load or times out | The security group or firewall does not allow your current IP on the HTTPS port (your IP may have changed) |
| `401 Unauthorized` | Wrong password: read `.gateway/credentials.txt` |
| `421 Misdirected Request` | The address must use the installed host name and port: no port for 443, `:8000` only if you installed with `gateway.port=8000` |
| `403` when launching an attack | You are signed in as `learner`: sign in as `operator` |

More, with the exact recovery for each: [Troubleshooting, installer failures](TROUBLESHOOTING.md#installer-common-failures-and-exact-recovery).

## Going further

| Topic | Where |
|---|---|
| All configuration keys, upgrade, backup, uninstall, measured figures | [Installer reference](INSTALLER.md#reference-requirements-configuration-and-maintenance) |
| Certificates, your own certificate, authentication, remote access in depth | [Gateway reference](GATEWAY.md#reference-the-installers-gateway-certificates-and-remote-access) |
| Splunk, search access for the notebook, kernel note, optional dashboards | [Splunk integration reference](SPLUNK_INTEGRATION.md#reference-the-installers-bundled-splunk-search-access-kernel-and-known-issues) |
| Cloud VM settings used in testing | [Installer reference](INSTALLER.md#cloud-vm-settings-used-in-testing) |
| What to do in the Academy | [Learner guide](LEARNER_GUIDE.md) |
