from agentsec.json_strict import DuplicateJsonKeyError, loads_json_no_duplicate_keys
import pytest


def test_duplicate_keys_are_rejected_at_top_level():
    with pytest.raises(DuplicateJsonKeyError):
        loads_json_no_duplicate_keys('{"a": 1, "a": 2}')


def test_duplicate_nested_argument_keys_are_rejected():
    raw = '{"tool":"lookup_policy","arguments":{"policy_id":"lending-basics","policy_id":"executive-restricted"},"requested_scope":"policy:read"}'
    with pytest.raises(DuplicateJsonKeyError) as exc:
        loads_json_no_duplicate_keys(raw)
    assert exc.value.args[0] == "policy_id"


def test_valid_object_parses():
    data = loads_json_no_duplicate_keys(
        '{"tool":"lookup_policy","arguments":{"policy_id":"lending-basics"},"requested_scope":"policy:read"}'
    )
    assert data["arguments"]["policy_id"] == "lending-basics"
