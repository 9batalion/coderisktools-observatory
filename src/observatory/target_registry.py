"""Append-only local target registry."""

from dataclasses import asdict
import json
from pathlib import Path

from observatory.contracts import ContractError, Target


class RegistryError(ValueError):
    """Raised when a registry is malformed or conflicts with a target."""


def load_targets(path):
    path = Path(path)
    if path.is_symlink():
        raise RegistryError("registry symlink is not allowed")
    if not path.exists():
        return []
    targets = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise RegistryError("registry cannot be read") from exc
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            targets.append(Target.from_dict(json.loads(line)))
        except (ValueError, TypeError, json.JSONDecodeError, ContractError) as exc:
            raise RegistryError(f"invalid registry line {number}") from exc
    return targets


def add_target(path, target):
    if not isinstance(target, Target):
        raise RegistryError("Target required")
    path = Path(path)
    existing = load_targets(path)
    for item in existing:
        if item.target_id == target.target_id and item.requested_ref == target.requested_ref:
            if item.resolved_sha != target.resolved_sha:
                raise RegistryError("target ref already exists with a different SHA")
            return item
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise RegistryError("registry symlink is not allowed")
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(asdict(target), ensure_ascii=False, sort_keys=True) + "\n")
    return target
