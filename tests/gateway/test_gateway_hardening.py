"""Runtime checks of the gateway's abuse controls in the ISOLATED stack (project agentsec-gw-dev). Opt-in like test_gateway_runtime.py."""
import os, time
import pytest
from gwhelpers import needs_docker, needs_openssl
from test_gateway_runtime import HOST, PORT, stack  # noqa: F401

pytestmark = [needs_docker, needs_openssl, pytest.mark.skipif(os.environ.get("AGENTSEC_GATEWAY_RUNTIME_TESTS") != "1", reason="opt-in: starts an isolated compose project; set AGENTSEC_GATEWAY_RUNTIME_TESTS=1")]
J = ["Content-Type: application/json"]
ATTACK_POST = "/api/missions/loan-desk/runs"          # a state-changing attack-tier route


def _post(stack, user, path=ATTACK_POST):
    return stack.curl(path, user=user, method="POST", data="{}", headers=J)


def _drain(stack):
    """Spend the operator's quota; returns the statuses seen."""
    return [_post(stack, "operator").status for _ in range(14)]


def test_unauthorized_requests_cannot_spend_the_operators_attack_quota(stack):
    time.sleep(65)                                                                  # start from a full bucket
    anon = [stack.curl(ATTACK_POST, method="POST", data="{}", headers=J).status for _ in range(40)]
    learner = [_post(stack, "learner").status for _ in range(40)]
    assert set(anon) == {401} and set(learner) == {403}, (set(anon), set(learner))   # never 429: nothing was charged
    first = [_post(stack, "operator").status for _ in range(6)]                        # the full burst is still available to the operator
    assert 429 not in first and not {401, 403} & set(first), first


def test_quota_applies_to_execution_posts_only_and_returns_retry_after(stack):
    time.sleep(65)
    polls = [stack.curl("/api/launches/abc123", user="operator").status for _ in range(30)]   # GET status polling
    assert 429 not in polls and not {401, 403} & set(polls), set(polls)
    codes = _drain(stack)
    assert 429 in codes and codes.index(429) <= 8, codes
    over = _post(stack, "operator")
    assert over.status == 429 and over.headers.get("retry-after") == ["10"]
    assert stack.curl("/api/launches/abc123", user="operator").status != 429                    # polling still works while the quota is spent
    assert _post(stack, "learner").status == 403                                              # and a learner is told 403, not 429, even now


def test_the_quota_recovers(stack):
    _drain(stack)
    time.sleep(15)                                                                  # rate 6/min: about one token per 10 s
    assert _post(stack, "operator").status not in (429, 401, 403)
