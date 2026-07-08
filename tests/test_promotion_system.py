from __future__ import annotations

import types
from pathlib import Path

from kata.agent_bundle import AGENT_MANIFEST_FILENAME, write_agent_manifest
from kata.evaluators.sn60_bitsec import hash_bundle_root
from kata.lane_state import (
    LANE_METADATA_SCHEMA_VERSION,
    EvaluatorLaneMetadata,
    load_lane_king_state,
    write_lane_metadata,
)
from kata.promotion_system import (
    find_evaluator_pack_entry,
    promote_lane_king,
    resolve_sn60_lane_king_hash,
    validate_submission_lane,
)
from kata.screening_system.rules import hash_submission_bundle


def write_lane(public_root: Path, *, active: bool = True) -> None:
    write_lane_metadata(
        EvaluatorLaneMetadata(
            schema_version=LANE_METADATA_SCHEMA_VERSION,
            lane_id="sn60__bitsec",
            repo_pack="sn60__bitsec",
            mode="miner",
            evaluator_id="sn60_bitsec",
            evaluator_policy_version="v1",
            active=active,
            created_at="2026-07-01T00:00:00+00:00",
            updated_at="2026-07-01T00:00:00+00:00",
        ),
        public_root=str(public_root),
    )


def write_bundle(root: Path, source: str = "def agent_main():\n    return {}\n") -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "agent.py").write_text(source, encoding="utf-8")
    write_agent_manifest(root / AGENT_MANIFEST_FILENAME)


def test_find_evaluator_pack_entry_and_validate_lane(tmp_path: Path) -> None:
    write_lane(tmp_path)

    entry = find_evaluator_pack_entry("sn60__bitsec", "miner", public_root=str(tmp_path))

    assert entry is not None
    assert entry.lane_id == "sn60__bitsec"
    assert validate_submission_lane("sn60__bitsec", "miner", public_root=str(tmp_path)) == []


def test_resolve_sn60_lane_king_hash_falls_back_to_published_king(
    tmp_path: Path,
) -> None:
    write_bundle(tmp_path / "kings/sn60__bitsec/miner")

    assert resolve_sn60_lane_king_hash(
        "sn60__bitsec",
        repo_pack="sn60__bitsec",
        mode="miner",
        public_root=str(tmp_path),
    ) == hash_submission_bundle(tmp_path / "kings/sn60__bitsec/miner")


def test_promote_lane_king_publishes_bundle_and_updates_lane_state(
    tmp_path: Path,
) -> None:
    write_lane(tmp_path)
    candidate_root = tmp_path / "candidate"
    write_bundle(candidate_root, "def agent_main():\n    return {'ok': True}\n")
    entry = find_evaluator_pack_entry("sn60__bitsec", "miner", public_root=str(tmp_path))
    assert entry is not None
    verification = types.SimpleNamespace(
        repo_pack="sn60__bitsec",
        mode="miner",
        submission_id="alice-20260708-01",
        submission_path=str(candidate_root),
        candidate_artifact_hash=hash_submission_bundle(candidate_root),
    )
    summary = types.SimpleNamespace(run_id="sn60-run-1")

    result = promote_lane_king(
        entry=entry,
        verification=verification,
        summary=summary,  # type: ignore[arg-type]
        public_root=str(tmp_path),
    )

    king_root = tmp_path / "kings/sn60__bitsec/miner"
    king_state = load_lane_king_state("sn60__bitsec", public_root=str(tmp_path))
    assert result.king_root == str(king_root)
    assert (king_root / "agent.py").read_text(encoding="utf-8").strip() == (
        "def agent_main():\n    return {'ok': True}"
    )
    assert king_state.current_king_submission_id == "alice-20260708-01"
    assert king_state.current_king_artifact_hash == hash_bundle_root(king_root)
    assert result.king.current_king_artifact_hash == hash_bundle_root(king_root)
