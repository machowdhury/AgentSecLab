from agentsec.attacks import BENIGN_LOAN
from agentsec.baseline import BaselineTicker
from agentsec.pipeline import run_loan_pipeline


def test_baseline_tick_uses_in_process_runner(settings, stub_llm, memory):
    def run_fn(text: str):
        return run_loan_pipeline(
            text,
            llm=stub_llm,
            sink=memory,
            memory=memory,
            settings=settings,
            user_id="baseline-ticker",
            testbed_mode="BASELINE",
            attack_id="ATK-001",
        )

    ticker = BaselineTicker(
        run_fn,
        enabled=True,
        interval_min=5,
        interval_max=5,
        startup_delay=0,
    )
    payload = ticker.tick_once()
    assert payload["ticks"] == 1
    assert payload["run_id"]
    assert payload["blocked"] is False
    modes = {event["agentsec.testbed.mode"] for event in memory.events}
    assert modes == {"BASELINE"}
    assert BENIGN_LOAN.split()[0]  # sanity: catalog still imported
