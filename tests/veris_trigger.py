"""
Trigger a real Veris sandbox simulation run via the Veris API.

Usage:
    python tests/veris_trigger.py --environment-id <id> --scenario-set-id <id>
    python tests/veris_trigger.py --environment-id <id> --scenario-set-id <id> --wait

Requires VERIS_API_KEY in .env
"""

import os
import sys
import time
import json
import argparse
import requests
from dotenv import load_dotenv

load_dotenv()

VERIS_BASE = "https://sandbox.api.veris.ai/v1"


def veris_headers() -> dict:
    key = os.getenv("VERIS_API_KEY")
    if not key:
        print("ERROR: VERIS_API_KEY not set in .env")
        sys.exit(1)
    return {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}


def trigger_run(environment_id: str, scenario_set_id: str, image_tag: str = "latest") -> dict:
    resp = requests.post(
        f"{VERIS_BASE}/runs",
        headers=veris_headers(),
        json={"environment_id": environment_id, "scenario_set_id": scenario_set_id, "image_tag": image_tag},
    )
    resp.raise_for_status()
    return resp.json()


def get_run(run_id: str) -> dict:
    resp = requests.get(f"{VERIS_BASE}/runs/{run_id}", headers=veris_headers())
    resp.raise_for_status()
    return resp.json()


def poll_until_done(run_id: str, interval: int = 10, timeout: int = 600) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        run = get_run(run_id)
        status = run.get("status", "")
        print(f"  status: {status}", flush=True)
        if status in ("completed", "failed", "cancelled"):
            return run
        time.sleep(interval)
    raise TimeoutError(f"Run {run_id} did not complete within {timeout}s")


def list_simulations(run_id: str) -> dict:
    resp = requests.get(f"{VERIS_BASE}/runs/{run_id}/simulations", headers=veris_headers())
    resp.raise_for_status()
    return resp.json()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--environment-id",  required=True)
    parser.add_argument("--scenario-set-id", required=True)
    parser.add_argument("--image-tag",       default="latest")
    parser.add_argument("--wait",            action="store_true", help="poll until run completes")
    args = parser.parse_args()

    print(f"Triggering Veris run: env={args.environment_id} set={args.scenario_set_id}")
    run = trigger_run(args.environment_id, args.scenario_set_id, args.image_tag)
    run_id = run["id"]
    print(f"Run created: {run_id}")
    print(f"  View: https://sandbox.api.veris.ai/runs/{run_id}")

    if args.wait:
        print("Polling for completion...")
        run = poll_until_done(run_id)
        print(f"\nFinal status: {run['status']}")
        sims = list_simulations(run_id)
        print(json.dumps(sims, indent=2))
    else:
        print("Run triggered. Check status with:")
        print(f"  python tests/veris_trigger.py --environment-id {args.environment_id} --scenario-set-id {args.scenario_set_id} --wait")
