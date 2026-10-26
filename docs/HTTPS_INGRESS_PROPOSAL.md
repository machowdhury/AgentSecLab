# HTTPS ingress: proposal and local proof of concept

**Status: PROPOSAL. Nothing in this document is deployed.** It changes no AWS security group, DNS record, certificate or port. Approval gates are listed at the end.

## Current topology
All services bind to `127.0.0.1` by default (`AGENTSEC_BIND_ADDRESS`). Academy and Attack Service share port 5001, AcmeBank is 5000, Splunk Web is 8000. HEC (8088) and OTel (4317, 4318) are always loopback; Splunk management (8089), Ollama and the verifier are never published. There is no TLS and no authentication in the applications. Reaching a remote lab today means an SSH or SSM tunnel (see [Remote access](REMOTE_ACCESS.md)).

## Proposed topology
One reverse proxy is the only listener on 443; the existing bindings stay as they are. It serves three hostnames with the same certificate and the same authentication gate.

| Hostname (placeholder) | Upstream | Policy |
|---|---|---|
| `learn.<domain>` | Attack Service `:5001` | Read-only allowlist: `/learn`, `/static`, `/api/learn/config`, `/api/academy/status`. Everything else 404. |
| same hostname, attack tier | `:5001` | Only the mission and launch routes in `attack-tier.conf`; authenticated, rate-limited (6 per minute, burst 10), 64 KB body limit. One line in `nginx.conf` removes the whole tier. |
| `bank.<domain>` | AcmeBank `:5000` | GET only. |
| `splunk.<domain>` | Splunk Web `:8000` | Proxy only; Splunk keeps its own login. WebSocket upgrade allowed. |

Never proxied: 8088 (HEC), 4317 and 4318 (OTel), 8089 (Splunk management), Ollama, the verifier, and the Attack Service routes not listed (`/api/allowlist`, `/api/compare-handoff`, evidence endpoints, and so on).

## Security boundaries
- **TLS:** 1.2 or newer, HSTS, HTTP redirects to HTTPS (308), server version hidden. Production needs a certificate that browsers validate (ACME on a real domain or a trusted internal CA). No verification bypass, no click-through self-signed certificate.
- **Authentication:** the PoC uses HTTP basic auth to prove the gate. For production choose OIDC (for example `oauth2-proxy`) or per-learner credentials; this is an approval gate. The `Authorization` header is stripped before it reaches upstreams.
- **Access control:** the source CIDR for 443 must be the workshop network, never `0.0.0.0/0`. The lab has no learner isolation, so one trusted learner or instructor group per deployment.
- **Attack execution:** the one deliberate exposure. An authenticated user can launch the educational attacks against AcmeBank. Disable the attack tier for read-only audiences.

## Local proof of concept
`deploy/https-poc/` runs the real Attack Service and AcmeBank on `127.0.0.1` (offset ports 15000 and 15001) and nginx in Docker published on `127.0.0.1:8443` and `:8080` only, with a throwaway CA and password. `sh deploy/https-poc/run.sh` removes everything on exit. Result on this change: **17 of 17 checks passed** (TLS, credentials, 401 without or with a wrong password, GET-only tiers, 404 for unlisted paths, TLS 1.1 refusal, HTTP redirect, unknown CA rejected, HSTS, rate limit). Splunk was not running, so the Splunk hostname was only shown to route (502). WebSockets, the full Mission UI through the proxy, and a browser pass were **not tested**.

## Rollback
Stop and remove the proxy service, remove the 443 security-group rule, and restore the prior compose file. Verify the security-group hash returns to its pre-change value and the listening-socket hash is unchanged.

## Approval gates (each needs an explicit yes)
1. Proxy configuration and the compose diff.
2. Domain name and DNS records.
3. Certificate or ACME account.
4. Security-group rule for 443 and its source CIDR.
5. Authentication method and credential distribution.
6. Whether the attack tier is enabled for the audience.
