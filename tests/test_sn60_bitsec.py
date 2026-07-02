from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from kata.evaluators.sn60_bitsec import (
    Sn60ReplicaContext,
    build_bitsec_execution_command,
    extract_evaluation_metrics,
    project_passes,
    resolve_sn60_sandbox_source,
    run_sn60_bitsec_duel,
)


def write_bundle(root: Path, *, agent_source: str, helper_source: str | None = None) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "agent.py").write_text(agent_source, encoding="utf-8")
    if helper_source is not None:
        helpers_root = root / "helpers"
        helpers_root.mkdir()
        (helpers_root / "planner.py").write_text(helper_source, encoding="utf-8")


def write_sandbox_source(root: Path) -> Path:
    benchmark_path = root / "validator" / "curated-highs-only-2025-08-08.json"
    benchmark_path.parent.mkdir(parents=True, exist_ok=True)
    benchmark_path.write_text(
        json.dumps(
            [
                {
                    "project_id": "project-alpha",
                    "vulnerabilities": [{"title": "expected alpha"}],
                }
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    return benchmark_path


def test_run_sn60_bitsec_duel_stages_full_bundle_and_persists_outputs(tmp_path: Path) -> None:
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = write_sandbox_source(sandbox_root)
    king_root = tmp_path / "king"
    candidate_root = tmp_path / "candidate"
    write_bundle(
        king_root,
        agent_source="def agent_main():\n    return {'vulnerabilities': []}\n",
        helper_source="VALUE = 'king-helper'\n",
    )
    write_bundle(
        candidate_root,
        agent_source="def agent_main():\n    return {'vulnerabilities': []}\n",
        helper_source="VALUE = 'candidate-helper'\n",
    )

    staged_helpers: dict[tuple[str, str, int], str] = {}

    def execute(context: Sn60ReplicaContext) -> dict[str, object]:
        helper_path = Path(context.bundle_root) / "helpers" / "planner.py"
        staged_helpers[(context.variant_name, context.project_key, context.replica_index)] = (
            helper_path.read_text(encoding="utf-8")
        )
        return {
            "success": True,
            "report": {
                "project": context.project_key,
                "vulnerabilities": [
                    {
                        "title": (
                            f"{context.variant_name}-"
                            f"{context.project_key}-{context.replica_index}"
                        ),
                    }
                ],
            },
        }

    def evaluate(
        context: Sn60ReplicaContext,
        report_payload: dict[str, object],
    ) -> dict[str, object]:
        detection_rate = 1.0 if context.variant_name == "candidate" else 0.25
        if context.project_key == "project-beta" and context.replica_index == 2:
            return {"status": "error", "error": "forced failure", "result": {}}
        return {
            "status": "success",
            "result": {
                "project": context.project_key,
                "timestamp": "2026-07-01T00:00:00+00:00",
                "total_expected": 4,
                "total_found": len(report_payload["report"]["vulnerabilities"]),
                "true_positives": int(detection_rate * 4),
                "false_negatives": 4 - int(detection_rate * 4),
                "false_positives": 0,
                "detection_rate": detection_rate,
                "precision": 1.0,
                "f1_score": detection_rate,
                "result": "PASS" if detection_rate == 1.0 else "FAIL",
                "matched_findings": [],
                "missed_findings": [],
                "extra_findings": [],
                "undecided_findings": [],
            },
        }

    summary = run_sn60_bitsec_duel(
        king_artifact_path=str(king_root),
        candidate_artifact_path=str(candidate_root),
        project_keys=["project-alpha", "project-beta"],
        output_root=str(tmp_path / "runs"),
        replicas_per_project=2,
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark_path),
        sandbox_commit="sandbox-commit-123",
        execution_hook=execute,
        evaluation_hook=evaluate,
    )

    assert summary.sandbox_source.sandbox_commit == "sandbox-commit-123"
    assert summary.sandbox_source.benchmark_file == str(benchmark_path.resolve())
    assert summary.king.invalid_runs == 1
    assert summary.candidate.invalid_runs == 1
    assert summary.king.average_detection_rate == 0.1875
    assert summary.candidate.average_detection_rate == 0.75
    assert summary.candidate.pass_count == 3
    # candidate passes project-alpha (2/2 runs) but not project-beta (1 pass, 1 invalid)
    assert summary.candidate.codebase_pass_count == 1
    assert summary.candidate.aggregated_score == 0.5
    assert summary.king.codebase_pass_count == 0
    assert summary.king.aggregated_score == 0.0
    candidate_projects = {
        project.project_key: project.passed for project in summary.candidate.project_summaries
    }
    assert candidate_projects == {"project-alpha": True, "project-beta": False}

    duel_summary_path = Path(summary.output_root) / "duel_summary.json"
    assert duel_summary_path.exists()

    persisted = json.loads(duel_summary_path.read_text(encoding="utf-8"))
    assert persisted["run_id"] == summary.run_id
    assert persisted["candidate"]["project_summaries"][0]["project_key"] == "project-alpha"

    candidate_helper = staged_helpers[("candidate", "project-alpha", 1)]
    king_helper = staged_helpers[("king", "project-alpha", 1)]
    assert "candidate-helper" in candidate_helper
    assert "king-helper" in king_helper

    for variant_name in ("king", "candidate"):
        report_path = (
            Path(summary.output_root)
            / variant_name
            / "project-alpha"
            / "replica-01"
            / "reports"
            / "project-alpha"
            / "report.json"
        )
        evaluation_path = report_path.with_name("evaluation.json")
        assert report_path.exists()
        assert evaluation_path.exists()


def test_build_bitsec_execution_command_mounts_bundle_and_sets_pythonpath(tmp_path: Path) -> None:
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = write_sandbox_source(sandbox_root)
    source = resolve_sn60_sandbox_source(
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark_path),
        sandbox_commit="commit-1",
        scorer_version="ScaBenchScorerV2",
    )
    context = Sn60ReplicaContext(
        run_id="run-1",
        variant_name="candidate",
        project_key="project-alpha",
        replica_index=1,
        bundle_root=str(tmp_path / "bundle"),
        reports_root=str(tmp_path / "reports" / "project-alpha"),
        report_path=str(tmp_path / "reports" / "project-alpha" / "report.json"),
        evaluation_path=str(tmp_path / "reports" / "project-alpha" / "evaluation.json"),
        sandbox_source=source,
    )

    command = build_bitsec_execution_command(context)

    assert command[:4] == ["docker", "run", "--rm", "--network"]
    assert "AGENT_FILE=/kata_bundle/agent.py" in command
    assert "PYTHONPATH=/kata_bundle" in command
    assert "INFERENCE_API_KEY" in command
    assert f"JOB_RUN_ID={context.run_id}" in command
    assert f"PROJECT_KEY={context.project_key}" in command
    assert command[-1] == "ghcr.io/bitsec-ai/project-alpha:latest"


def test_project_passes_requires_two_of_three_runs() -> None:
    assert project_passes(pass_count=2, replica_count=3)
    assert project_passes(pass_count=3, replica_count=3)
    assert not project_passes(pass_count=1, replica_count=3)
    assert not project_passes(pass_count=0, replica_count=3)
    assert project_passes(pass_count=1, replica_count=1)
    assert not project_passes(pass_count=1, replica_count=2)
    assert not project_passes(pass_count=0, replica_count=0)


def test_resolve_sn60_sandbox_source_rejects_mismatched_pinned_commit(
    tmp_path: Path,
) -> None:
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = write_sandbox_source(sandbox_root)
    subprocess.run(["git", "init", "--quiet", str(sandbox_root)], check=True)
    subprocess.run(["git", "-C", str(sandbox_root), "add", "-A"], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(sandbox_root),
            "-c",
            "user.name=kata-test",
            "-c",
            "user.email=kata-test@example.com",
            "commit",
            "--quiet",
            "-m",
            "seed",
        ],
        check=True,
    )
    head = subprocess.run(
        ["git", "-C", str(sandbox_root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    source = resolve_sn60_sandbox_source(
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark_path),
        sandbox_commit=head,
        scorer_version="ScaBenchScorerV2",
    )
    assert source.sandbox_commit == head

    with pytest.raises(ValueError, match="does not match the checked-out sandbox"):
        resolve_sn60_sandbox_source(
            sandbox_root=str(sandbox_root),
            benchmark_file=str(benchmark_path),
            sandbox_commit="0" * 40,
            scorer_version="ScaBenchScorerV2",
        )


def test_extract_evaluation_metrics_gates_all_metrics_on_success() -> None:
    metrics = extract_evaluation_metrics(
        {
            "status": "error",
            "result": {
                "detection_rate": 1.0,
                "true_positives": 8,
                "total_expected": 8,
                "total_found": 8,
                "result": "PASS",
            },
        }
    )

    assert metrics["evaluation_status"] == "error"
    assert metrics["score"] == 0.0
    assert metrics["detection_rate"] == 0.0
    # A failed evaluation must not contribute a PASS or true positives; the
    # king variant is never invalid-gated, so ungated metrics would inflate
    # the promotion bar.
    assert metrics["result"] is None
    assert metrics["true_positives"] == 0
    assert metrics["total_expected"] == 0
    assert metrics["total_found"] == 0


def test_extract_evaluation_metrics_keeps_metrics_for_success() -> None:
    metrics = extract_evaluation_metrics(
        {
            "status": "success",
            "result": {
                "detection_rate": 0.75,
                "true_positives": 6,
                "total_expected": 8,
                "total_found": 7,
                "result": "PASS",
            },
        }
    )

    assert metrics["evaluation_status"] == "success"
    assert metrics["score"] == 0.75
    assert metrics["result"] == "PASS"
    assert metrics["true_positives"] == 6
    assert metrics["total_expected"] == 8
    assert metrics["total_found"] == 7


def test_execution_subprocess_env_strips_validator_scoring_secrets(
    monkeypatch,
) -> None:
    from kata.evaluators.sn60_bitsec import execution_subprocess_env

    monkeypatch.setenv("CHUTES_API_KEY", "scoring-key")
    monkeypatch.setenv("KATA_VALIDATOR_API_KEY", "validator-key")
    monkeypatch.setenv("INFERENCE_API_KEY", "miner-key")

    env = execution_subprocess_env()

    assert "CHUTES_API_KEY" not in env
    assert "KATA_VALIDATOR_API_KEY" not in env
    assert env["INFERENCE_API_KEY"] == "miner-key"


def test_build_bitsec_evaluation_command_quotes_interpolated_values(
    tmp_path: Path,
) -> None:
    from kata.evaluators.sn60_bitsec import build_bitsec_evaluation_command

    context = Sn60ReplicaContext(
        run_id="run-1",
        variant_name="candidate",
        project_key="project'; import os; os.system('x'); '",
        replica_index=1,
        bundle_root=str(tmp_path / "bundle"),
        reports_root=str(tmp_path / "reports" / "project-a"),
        report_path=str(tmp_path / "reports" / "project-a" / "report.json"),
        evaluation_path=str(tmp_path / "reports" / "project-a" / "evaluation.json"),
        sandbox_source=None,
    )

    command = build_bitsec_evaluation_command(context)

    script = command[-1]
    # The hostile project key must survive as a single quoted literal instead
    # of terminating the string and injecting statements.
    assert repr(context.project_key) in script
    import ast

    ast.parse(script)
