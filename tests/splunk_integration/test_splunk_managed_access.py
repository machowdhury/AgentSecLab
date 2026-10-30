"""Installer-managed Splunk access: the access directory, a recorded trust anchor with a recorded server name, and the basic-auth variant.
MOCK ONLY (mock_splunk.py): this proves the client's behaviour, not Splunk's. Verification against a real Splunk is checkpoint 5 and needs its own approval."""
import shutil, subprocess, sys
from pathlib import Path
import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path[:0] = [str(ROOT / "src"), str(HERE), str(ROOT / "tests" / "gateway")]
import mock_splunk as ms                                                   # noqa: E402
from gwhelpers import make_ca, make_leaf, needs_openssl                    # noqa: E402
from agentsec import splunk_client as sc                                   # noqa: E402

pytestmark = needs_openssl
DEFAULT_CN = "SplunkServerDefaultCert"


def self_signed_no_san(d: Path, cn: str, *extra):
    """Stands in for Splunk's default management certificate: self-signed, a CN and no subject alternative name."""
    d.mkdir(parents=True, exist_ok=True)
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "30", "-subj", f"/CN={cn}", "-keyout", str(d / "k.pem"), "-out", str(d / "c.pem"),
                    "-addext", "basicConstraints=CA:FALSE", "-addext", "keyUsage=digitalSignature,keyEncipherment", "-addext", "extendedKeyUsage=serverAuth", *extra],
                   check=True, capture_output=True)
    return d / "c.pem", d / "k.pem"


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    d = tmp_path_factory.mktemp("managed")
    ca, cak = make_ca(d / "ca", "mock-ca")
    good = make_leaf(d / "good", ca, cak, "DNS:splunk.test,IP:127.0.0.1")
    default = self_signed_no_san(d / "default", DEFAULT_CN)
    other = self_signed_no_san(d / "other", "SomeOtherName")
    expired = make_leaf(d / "exp", ca, cak, "DNS:splunk.test,IP:127.0.0.1", "server", "-not_before", "20200101000000Z", "-not_after", "20200102000000Z")
    srv = {"good": ms.start(*good), "default": ms.start(*default), "other": ms.start(*other), "expired": ms.start(*expired)}
    yield {"dir": d, "good": good[0], "default": default[0], "other": other[0], "expired": expired[0], "srv": srv}
    for s in srv.values():
        s.shutdown()


def access_dir(tmp_path, anchor, *, auth="basic", cred=None, name=DEFAULT_CN, user=None, folder="access"):
    d = tmp_path / folder
    d.mkdir(exist_ok=True)
    (d / "auth").write_text(auth); (d / "credential").write_text(cred if cred is not None else ("pw-ok" if auth == "basic" else ms.TOK_SEARCH_ONLY))
    (d / "server_name").write_text(name); shutil.copy(anchor, d / "ca.pem")
    if user: (d / "user").write_text(user)
    for f in d.iterdir(): f.chmod(0o600)
    return d


def env(pki, d, server="default", **over):
    e = {"AGENTSEC_SPLUNK_MODE": "BUNDLED", "AGENTSEC_SPLUNK_REST_URL": f"https://127.0.0.1:{pki['srv'][server].server_port}",
         "AGENTSEC_SPLUNK_ACCESS_DIR": str(d), "AGENTSEC_SPLUNK_TIMEOUT_SEC": "2"}
    e.update(over); return e


OK = "| makeresults count=1 | eval ok=1"


def test_default_style_certificate_without_san_is_verified_against_its_recorded_name(pki, tmp_path):
    e = env(pki, access_dir(tmp_path, pki["default"]))
    assert sc.rest_configured(e)
    cfg = sc.config_from_env(e)
    assert (cfg.mode, cfg.auth, cfg.user, cfg.server_name) == ("BUNDLED", "basic", "agentsec_search", DEFAULT_CN)
    assert sc.client_for_mode(e).export_rows(OK)[0]["ok"] == "1"


def test_ca_signed_leaf_recorded_as_its_own_anchor_works(pki, tmp_path):
    e = env(pki, access_dir(tmp_path, pki["good"], name="splunk.test"), server="good")      # the leaf alone is the anchor: partial chain
    assert sc.client_for_mode(e).export_rows(OK)[0]["ok"] == "1"


def test_bearer_variant_works_too(pki, tmp_path):
    e = env(pki, access_dir(tmp_path, pki["default"], auth="bearer"))
    assert sc.config_from_env(e).auth == "bearer" and sc.client_for_mode(e).export_rows(OK)[0]["ok"] == "1"


def test_a_different_certificate_on_the_address_is_refused_before_any_request(pki, tmp_path):
    ms.Handler.seen.clear()
    e = env(pki, access_dir(tmp_path, pki["default"]), server="other")                      # anchor says one certificate, the server presents another
    with pytest.raises(sc.SplunkError) as exc:
        sc.client_for_mode(e).export_rows(OK)
    assert (exc.value.stage, exc.value.code) == ("connectivity", "tls_verification_failed")
    assert ms.Handler.seen == []                                                             # the credential never travelled


def test_wrong_recorded_server_name_is_refused(pki, tmp_path):
    with pytest.raises(sc.SplunkError) as exc:
        sc.client_for_mode(env(pki, access_dir(tmp_path, pki["default"], name="SomeOtherName"))).export_rows(OK)
    assert exc.value.code == "tls_verification_failed"


def test_an_expired_certificate_is_refused_even_when_it_is_the_anchor(pki, tmp_path):
    with pytest.raises(sc.SplunkError) as exc:
        sc.client_for_mode(env(pki, access_dir(tmp_path, pki["expired"], name="splunk.test"), server="expired")).export_rows(OK)
    assert exc.value.code == "tls_verification_failed"


def test_wrong_basic_password_is_an_authentication_failure(pki, tmp_path):
    with pytest.raises(sc.SplunkError) as exc:
        sc.client_for_mode(env(pki, access_dir(tmp_path, pki["default"], cred="not-the-password"))).export_rows(OK)
    assert (exc.value.stage, exc.value.code) == ("authentication", "auth_failed")


def test_missing_or_invalid_files_mean_unavailable_never_unverified_tls(pki, tmp_path):
    good = access_dir(tmp_path, pki["default"])
    assert sc.access_config(env(pki, good)) is not None
    for name in ("auth", "credential", "server_name", "ca.pem"):
        d = access_dir(tmp_path, pki["default"], folder="miss_" + name); (d / name).unlink()
        assert sc.access_config(env(pki, d)) is None and not sc.rest_configured(env(pki, d)), name
    assert sc.access_config(env(pki, access_dir(tmp_path, pki["default"], auth="digest", folder="a"))) is None
    assert sc.access_config(env(pki, access_dir(tmp_path, pki["default"], user="bad user;", folder="b"))) is None
    assert sc.access_config(env(pki, access_dir(tmp_path, pki["default"], name="bad name;", folder="c"))) is None
    garbage = access_dir(tmp_path, pki["default"], folder="g"); (garbage / "ca.pem").write_text("not a certificate")
    assert sc.access_config(env(pki, garbage)) is None
    assert sc.access_config(env(pki, good, AGENTSEC_SPLUNK_REST_URL="http://splunk:8089")) is None
    assert sc.access_config(env(pki, good, AGENTSEC_SPLUNK_REST_URL="https://u:p@splunk:8089")) is None
    assert sc.access_config({"AGENTSEC_SPLUNK_ACCESS_DIR": str(good)}) is None               # no REST URL
    assert sc.config_from_env(env(pki, tmp_path / "nope")).rest_url == ""                    # the bare BUNDLED config: callers must say 'unavailable'


def test_directory_is_read_on_every_call_so_provisioning_needs_no_restart(pki, tmp_path):
    e = env(pki, tmp_path / "late")
    assert not sc.rest_configured(e)
    access_dir(tmp_path, pki["default"], folder="late")
    assert sc.rest_configured(e) and sc.client_for_mode(e).export_rows(OK)[0]["ok"] == "1"


def test_credentials_never_appear_in_text_forms(pki, tmp_path):
    cfg = sc.config_from_env(env(pki, access_dir(tmp_path, pki["default"])))
    assert "pw-ok" not in str(cfg) and "pw-ok" not in repr(cfg)


def test_diagnose_reports_each_stage_for_the_managed_client(pki, tmp_path):
    res = {s: st for s, st, _ in sc.client_for_mode(env(pki, access_dir(tmp_path, pki["default"]))).diagnose()}
    assert [res[k] for k in ("connectivity", "authentication", "authorization", "search")] == ["PASS"] * 4


def test_unknown_auth_or_bad_name_cannot_build_a_client():
    for kw in ({"auth": "digest"}, {"auth": "basic", "user": "x y"}, {"server_name": "bad name;"}):
        with pytest.raises(sc.SplunkError):
            sc.SplunkRestClient(sc.SplunkConfig("BUNDLED", "https://splunk:8089", "", "x", **kw))
