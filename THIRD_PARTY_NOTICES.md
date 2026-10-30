# Third-party notices

AgentSecLab is licensed under the Apache License 2.0 ([LICENSE](LICENSE)). It uses the components below, each under its own licence. Licences were read from package metadata, the project's pin files and, for the tools below, each upstream `LICENSE` file on GitHub (2026-10-29).

## Python dependencies (`requirements.txt`, pinned)

| Package | Version | Licence |
|---|---|---|
| Flask | 3.0.3 | BSD-3-Clause |
| requests | 2.32.3 | Apache-2.0 |
| opentelemetry-api, -sdk, -exporter-otlp-proto-http | 1.44.0 | Apache-2.0 |
| jsonschema | 4.23.0 | MIT |
| python-dotenv | 1.0.1 | BSD-3-Clause |

## Academy front end (`academy-ui/package.json`, pinned)

| Package | Version | Licence |
|---|---|---|
| react, react-dom | 19.2.4 | MIT |
| @fontsource/manrope, @fontsource/dm-mono (fonts bundled in the build) | 5.3.0 | OFL-1.1 |
| vite, @vitejs/plugin-react, tailwindcss, @tailwindcss/vite (build only) | 8.0.5, 6.0.1, 4.2.2 | MIT |
| typescript, @types/* (build only) | 5.9.3 | Apache-2.0, MIT |

## Tools, images and models (not redistributed; fetched at install)

| Component | Licence |
|---|---|
| Cisco MCP Scanner 4.8.4 | Apache-2.0 |
| garak 0.17.0 (a recorded result is included, the tool is not) | Apache-2.0 |
| Ollama | MIT |
| Llama 3.2 models | Llama 3.2 Community License |
| Splunk Enterprise | Splunk's own terms |
| OpenTelemetry Collector contrib 0.96.0 | Apache-2.0 |
| nginx 1.27 | BSD-2-Clause |
| busybox 1.36, curl 8.5.0 (helper images), python 3.11 and 3.12 (base images) | GPL-2.0, curl licence, PSF; used as unmodified images, not redistributed |

The Cloud Security Alliance MAESTRO framework, NIST AI RMF, OWASP, MITRE ATLAS and ISO/IEC 42001 are referenced as publications; none of their text is reproduced beyond identifiers and short titles. Full tool detail: [docs/SECURITY_TOOLS.md](docs/SECURITY_TOOLS.md).

**Splunk terms.** The compose file starts Splunk with its licence-acceptance arguments, so running the bundled Splunk means you accept Splunk's own terms; read them first.

**Trademarks.** Splunk is a trademark of Splunk LLC, Cisco is a trademark of Cisco Systems, Inc., NVIDIA is a trademark of NVIDIA Corporation, and Llama, Ollama, nginx and the other names above belong to their owners. AgentSecLab is an independent project: it is not endorsed by, affiliated with or supported by any of them, and it names them only to say what it integrates with.
