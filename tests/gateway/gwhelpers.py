"""Helpers for the gateway tests: a throwaway PKI built with the openssl CLI, strict-TLS curl, protected-lab snapshot."""
import json, os, shutil, subprocess
from datetime import datetime, timezone
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[2]
needs_openssl = pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl CLI not available")
needs_docker = pytest.mark.skipif(shutil.which("docker") is None or subprocess.run(["docker", "info"], capture_output=True).returncode != 0, reason="docker not available")


def sh(*cmd, **kw):
    return subprocess.run([str(c) for c in cmd], capture_output=True, text=True, **kw)


def _ossl(*a):
    p = subprocess.run(["openssl", *map(str, a)], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    return p


def make_ca(d: Path, cn: str):
    d.mkdir(parents=True, exist_ok=True)
    _ossl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "30", "-subj", f"/CN={cn}", "-keyout", d / "ca.key", "-out", d / "ca.pem",
          "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    return d / "ca.pem", d / "ca.key"


def make_leaf(d: Path, ca_pem, ca_key, sans: str, name="server", *extra):
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{name}.ext").write_text(f"subjectAltName={sans}\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n")
    _ossl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=agentsec-test-server", "-keyout", d / f"{name}.key", "-out", d / f"{name}.csr")
    _ossl("x509", "-req", "-in", d / f"{name}.csr", "-CA", ca_pem, "-CAkey", ca_key, "-CAcreateserial", "-days", "30", "-extfile", d / f"{name}.ext", *extra, "-out", d / f"{name}.pem")
    (d / f"{name}.key").chmod(0o600)
    return d / f"{name}.pem", d / f"{name}.key"


def make_org_pki(base: Path, host="agentsec.test"):
    """root -> intermediate -> server, like an organization-issued certificate. Returns dict of file paths."""
    root_pem, root_key = make_ca(base / "root", "test-org-root")
    d = base / "int"; d.mkdir(exist_ok=True)
    _ossl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=test-org-intermediate", "-keyout", d / "ca.key", "-out", d / "i.csr")
    (d / "ext").write_text("basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n")
    _ossl("x509", "-req", "-in", d / "i.csr", "-CA", root_pem, "-CAkey", root_key, "-CAcreateserial", "-days", "30", "-extfile", d / "ext", "-out", d / "ca.pem")
    leaf, key = make_leaf(base / "leaf", d / "ca.pem", d / "ca.key", f"DNS:{host}")
    chain = base / "chain.pem"; chain.write_text((d / "ca.pem").read_text() + root_pem.read_text())
    return {"cert": leaf, "key": key, "chain": chain, "root": root_pem, "int_pem": d / "ca.pem", "int_key": d / "ca.key", "host": host}


def make_htpasswd(path: Path, learner="l-pass", operator="o-pass"):
    path.write_text(f"learner:{_ossl('passwd', '-apr1', learner).stdout.strip()}\noperator:{_ossl('passwd', '-apr1', operator).stdout.strip()}\n")
    return path


def base_env(tmp: Path, pki: dict, **over):
    env = {"AGENTSEC_TLS_MODE": "ORG_CERT", "AGENTSEC_PUBLIC_HOST": pki["host"], "AGENTSEC_HTTPS_PORT": "8443", "AGENTSEC_GATEWAY_DIR": str(tmp / "g"),
           "AGENTSEC_TLS_CERT_FILE": str(pki["cert"]), "AGENTSEC_TLS_KEY_FILE": str(pki["key"]), "AGENTSEC_TLS_CHAIN_FILE": str(pki["chain"]),
           "AGENTSEC_AUTH_FILE": str(make_htpasswd(tmp / "htpasswd"))}
    env.update(over)
    return env


def protected_snapshot():
    """Metadata of every container, volume and network that is NOT part of a gateway-dev project (the real lab)."""
    names = [n for n in sh("docker", "ps", "-a", "--format", "{{.Names}}").stdout.split() if n.startswith("agentsec_") and n != "agentsec_gateway"]
    cont = {}
    for n in sorted(names):
        i = json.loads(sh("docker", "inspect", n).stdout)[0]
        cont[n] = {"id": i["Id"], "image": i["Image"], "started": i["State"]["StartedAt"], "restarts": i["RestartCount"],
                   "mounts": sorted([m.get("Name") or m.get("Source"), m["Destination"]] for m in i["Mounts"]), "networks": sorted(i["NetworkSettings"]["Networks"])}
    vols = {v: json.loads(sh("docker", "volume", "inspect", v).stdout)[0]["CreatedAt"] for v in sorted(sh("docker", "volume", "ls", "-q").stdout.split()) if "agentsec-gw-dev" not in v}
    nets = sorted(n for n in sh("docker", "network", "ls", "--format", "{{.Name}}").stdout.split() if "agentsec-gw-dev" not in n)
    return json.loads(json.dumps({"containers": cont, "volumes": vols, "networks": nets}))
