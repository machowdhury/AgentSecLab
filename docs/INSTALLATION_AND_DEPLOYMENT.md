# Install AgentSecLab

Pick the one that matches you. Each path is a single sequence; you do not need to understand the architecture first.

| I want to run the lab… | Go to |
|---|---|
| **on this computer** and open it in this computer's browser | [LOCAL](#local-install-on-your-own-ubuntu-computer) |
| **on a remote Ubuntu server or cloud VM** and open it from my laptop | [REMOTE](#remote-ubuntu-server-or-cloud-vm-open-it-from-your-laptop) |

**Where this has been verified.** Ubuntu 24.04 LTS on x86-64 with Docker Engine, on a cloud VM (8 vCPU, 32 GiB RAM, 120 GiB disk). That is the only platform the install has been run on, end to end.

| Platform | Status |
|---|---|
| Ubuntu 24.04 x86-64, Docker Engine | **Verified** |
| macOS (Docker Desktop), Windows, other Linux, ARM, Podman, rootless Docker | **Not verified.** The installer's read-only checks start on a Mac and tell you what they find, but a full install has not been run there. Try it only if you accept that |
| Remote path with the lab on port 8000 and an SSH tunnel (used below) | **Not yet run on a real remote host.** The install and the gateway were verified on a real host; the 8000 port setting is covered by automated tests only |

The lab is for one learner on one machine and contains intentionally vulnerable agent profiles. Do not expose it to the internet. Measured disk, memory and timings are in the [installer reference](INSTALLER.md#requirements-measurements-and-platform-status); none of them is a minimum requirement.

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

## REMOTE: Ubuntu server or cloud VM, open it from your laptop

The lab runs on the server and listens only on the server's own loopback, so nothing is exposed to the network. Your laptop reaches it through an SSH tunnel. (The tunnel is the safe way in; the reason the port matters is explained in the [gateway reference](GATEWAY.md#authentication-and-remote-access).)

**You need:**
- *Server:* Ubuntu 24.04 x86-64, tested at 8 vCPU, 32 GiB RAM and 120 GiB disk, with `sudo`, internet access and SSH. For a cloud VM, allow only SSH (port 22) from your own IP address. **Do not open port 8000 or 443**; the tunnel does not need them. Check `uname -r`: if it starts with 6.19 or higher (the current Ubuntu AWS image ships 7.0), read the [kernel note](SPLUNK_INTEGRATION.md#kernel-619-or-newer-and-the-bundled-splunk) first. The lab was tested on kernel 6.8.
- *Laptop:* an SSH client and a browser. Port 8000 on your laptop must be free.

**On the server** (log in with `ssh <user>@<server>`):

**1. Install the tools.** Run step 1 of the LOCAL path, log out and back in, then:
```bash
git clone https://github.com/machowdhury/AgentSecLab.git
cd AgentSecLab
./agentsec preflight
```
**2. Install on port 8000** (about 10 minutes):
```bash
./agentsec --non-interactive --set gateway.ctf=true --set gateway.port=8000 --accept-warnings all --apply install
./agentsec status
```
`gateway.port=8000` is the only difference from LOCAL. It makes the Academy's address `https://localhost:8000`, which an unprivileged SSH tunnel can match exactly. Splunk Web moves to port 18000 automatically.

**On your laptop:**

**3. Copy the certificate and read the passwords** (replace `<user>` and `<server>`; the clone is in your home directory):
```bash
scp <user>@<server>:AgentSecLab/.gateway/tls/ca.pem ./agentseclab-ca.pem
ssh <user>@<server> cat AgentSecLab/.gateway/credentials.txt
```
**4. Trust the certificate.** Import `agentseclab-ca.pem` as a trusted authority, with the same browser steps as LOCAL step 4 (on macOS, double-click it, add it to Keychain Access, open it and set Trust to "Always Trust"). These steps have not been run on every system. Trust it only for this lab.

**5. Open the tunnel and the Academy:**
```bash
ssh -N -L 8000:127.0.0.1:8000 <user>@<server>        # leave this running
```
Open **https://localhost:8000/learn** and sign in as `operator` (launch attacks) or `learner` (read-only). If you see `421 Misdirected Request`, the port in the address is not 8000.

**Stop and restart:**
| Task | Where | Command |
|---|---|---|
| Close the tunnel | laptop | press Ctrl-C in the `ssh -N` window; run it again to reconnect |
| Stop the lab | server | `./agentsec down` (data is kept; a few minutes) |
| Start the lab | server | `./agentsec up`, then `./agentsec status` |

After a server reboot the lab restarts by itself. A cloud VM that is stopped but not deleted still costs for its disk: delete it when you are done.

---

## If something goes wrong

| You see | Do this |
|---|---|
| `permission denied` talking to Docker | Log out and back in after `usermod`; do not use `sudo ./agentsec` |
| `ERROR PORT_IN_USE` | Stop whatever uses that port, then run `preflight` again |
| `NOT READY` right after install | Splunk is still loading: wait a minute, run `./agentsec status` again |
| Browser certificate warning | Import the lab's CA (step 4); do not click through |
| `401 Unauthorized` | Wrong password: read `.gateway/credentials.txt` |
| `421 Misdirected Request` | The address must use the installed port: nothing for 443, `:8000` for the remote path |
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
