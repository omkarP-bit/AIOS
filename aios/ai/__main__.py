"""Run the Python planner against the Go control core.

    python -m aios.ai "how much memory is free?"

The planner proposes; the Go core decides. By default the proposal is a dry
run: the core authorizes but does not execute. ``--execute`` asks the core to
execute an allowed action. No approval token and no mutation shortcut exists
on this path.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from aios.ai.client import ControlClient, ControlError
from aios.ai.context import build_snapshot, render_snapshot
from aios.ai.planner import Planner, plan_to_dict
from aios.ai.providers import ProviderError, build_provider


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m aios.ai",
        description="Ask the AI planner to propose one action for the Go core.",
    )
    parser.add_argument("question", nargs="+", help="request in natural language")
    parser.add_argument("--execute", action="store_true", help="execute if the core allows it")
    parser.add_argument(
        "--no-context", action="store_true", help="do not attach an observation snapshot"
    )
    parser.add_argument("--api-url", default=None, help="Go core base URL")
    parser.add_argument("--json", action="store_true", help="print JSON")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    question = " ".join(args.question)

    try:
        client = ControlClient(args.api_url)
        catalog = client.schema()
        provider = build_provider()
        if provider.external:
            print(
                "warning: prompts leave this machine; AIOS_ALLOW_EXTERNAL_MODEL is set",
                file=sys.stderr,
            )
        context = "{}"
        if not args.no_context:
            context = render_snapshot(build_snapshot(client))
        plan = Planner(provider, catalog).propose(question, context)
    except (ControlError, ProviderError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if plan.request is None:
        reason = plan.reason or "no action proposed"
        if args.json:
            print(json.dumps({"decision": "NONE", "reason": reason}, sort_keys=True))
        else:
            print(f"NO ACTION: {reason}")
        return 0

    try:
        validated = client.validate(plan.request)
        if validated.get("valid") is not True:
            detail = validated.get("detail") or validated.get("error") or "invalid action"
            if args.json:
                print(
                    json.dumps(
                        {"plan": plan_to_dict(plan), "valid": False, "detail": detail},
                        sort_keys=True,
                    )
                )
            else:
                print(f"INVALID: {detail}")
            return 1
        status, verdict = client.execute(plan.request, dry_run=not args.execute)
    except ControlError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    output = {
        "plan": plan_to_dict(plan),
        "validated": True,
        "executed": bool(args.execute and status < 400),
        "status": status,
        "verdict": verdict,
    }
    if args.json:
        print(json.dumps(output, sort_keys=True))
    else:
        decision = verdict.get("decision", "UNKNOWN")
        reason = verdict.get("denial_reason") or verdict.get("reason") or ""
        mode = "executed" if args.execute else "not executed"
        print(f"{decision} {plan.request.action_name} ({mode})")
        if reason:
            print(f"  reason:   {reason}")
        if verdict.get("data") is not None:
            print(f"  data:     {json.dumps(verdict['data'], sort_keys=True)}")
        if not args.execute and verdict.get("executed") is False:
            print("  pass --execute to run an allowed action")
    return 0 if status < 400 else 1


if __name__ == "__main__":
    raise SystemExit(main())
