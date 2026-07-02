from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path

from kata.agent_bundle import load_bundle_files, replace_bundle_contents

KATA_REPO_ROOT = Path(__file__).resolve().parents[1]
KATA_ROOT_ENV = "KATA_ROOT"
KATA_ARTIFACT_SCHEME = "kata://"
PUBLIC_KINGS_DIRNAME = "kings"
KING_METADATA_FILENAME = "king.json"


@dataclass(frozen=True)
class PublicKingMetadata:
    repo_pack: str
    mode: str
    submission_id: str
    challenge_run_id: str
    king_artifact_hash: str
    candidate_artifact_hash: str


def resolve_kata_root(public_root: str | None = None) -> Path:
    configured_root = public_root or os.environ.get(KATA_ROOT_ENV)
    if configured_root:
        return Path(configured_root).expanduser().resolve()
    return KATA_REPO_ROOT.resolve()


def resolve_public_king_root(*, public_root: str | None, repo_pack: str, mode: str) -> Path:
    return resolve_kata_root(public_root) / PUBLIC_KINGS_DIRNAME / repo_pack / mode


def build_public_king_artifact_ref(*, repo_pack: str, mode: str) -> str:
    return f"{KATA_ARTIFACT_SCHEME}{PUBLIC_KINGS_DIRNAME}/{repo_pack}/{mode}"


def resolve_artifact_path(reference: str) -> Path:
    if reference.startswith(KATA_ARTIFACT_SCHEME):
        relative_path = reference.removeprefix(KATA_ARTIFACT_SCHEME).strip("/")
        if not relative_path:
            raise ValueError("Kata artifact reference is missing its relative path.")
        return (resolve_kata_root() / relative_path).resolve()
    return Path(reference).expanduser().resolve()


def mirror_public_king_artifact(
    *,
    public_root: str | None,
    repo_pack: str,
    mode: str,
    artifact_path: str,
) -> Path:
    king_root = resolve_public_king_root(
        public_root=public_root,
        repo_pack=repo_pack,
        mode=mode,
    )
    candidate_root = Path(artifact_path).expanduser().resolve()
    replace_bundle_contents(king_root, load_bundle_files(candidate_root))
    return king_root


def publish_public_king(
    *,
    public_root: str,
    repo_pack: str,
    mode: str,
    submission_id: str,
    challenge_run_id: str,
    candidate_artifact_path: str,
    king_artifact_hash: str,
    candidate_artifact_hash: str,
) -> Path:
    king_root = mirror_public_king_artifact(
        public_root=public_root,
        repo_pack=repo_pack,
        mode=mode,
        artifact_path=candidate_artifact_path,
    )
    metadata = PublicKingMetadata(
        repo_pack=repo_pack,
        mode=mode,
        submission_id=submission_id,
        challenge_run_id=challenge_run_id,
        king_artifact_hash=king_artifact_hash,
        candidate_artifact_hash=candidate_artifact_hash,
    )
    (king_root / KING_METADATA_FILENAME).write_text(
        json.dumps(asdict(metadata), indent=2) + "\n",
        encoding="utf-8",
    )
    return king_root
