"""Rollback detection through sync peers (Part B of the 2026-10-22 plan, 2026-10-29 update).

Every device publishes its vault generation and, for each peer, the highest
generation it has seen from that peer (its *witness*).  A device restored from
an old copy publishes a lower generation than before; the peers that were not
restored notice (``peer-vault-rollback``), and their witness of it is higher
than its own generation, so it notices too (``vault-rollback``).

Where the two values travel (``group.py`` format 2):

* in the header of a format-2 view, when every reader supports it, or
* in a *witness file* (a format-2 view with zero records) next to a format-1
  view while some member still runs a build that rejects format 2.

The rules here are pure (no I/O) so every platform can port them one for one:

* ``observe``: a peer generation below the remembered one gives
  ``peer-vault-rollback`` (detail: the peer id); the remembered value is never
  lowered.  A peer's ``witness[own_id]`` above ``own_generation`` raises
  ``rollback_suspected`` to that value.
* ``rollback_suspected`` is sticky: while it is non-zero every run reports
  ``vault-rollback`` (no detail), even after later saves raised the generation
  past it.  Only an explicit acknowledgement clears it (Task B4).
* A view without a generation (format 1 and no matching witness file) is not
  checked at all: nothing is reported and nothing is remembered.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from .engine import is_valid_id
from .group import FORMAT_WITNESS, MAX_WITNESS, View
from .runner import SyncIssue

MAX_GENERATION = 2**53 - 1


@dataclass(frozen=True)
class Observation:
    """One peer's published generation and witness, from a format-2 view or a witness file."""

    peer_id: str
    vault_generation: int
    witness: Mapping[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class WitnessResult:
    issues: tuple[SyncIssue, ...]
    peer_generations: dict[str, int]
    rollback_suspected: int
    #: Peer ids that showed format-2 support in this check.
    capable: frozenset[str] = frozenset()


def clamp_generation(generation: int) -> int:
    """A vault generation (0..2**63-1) as a header value (0..2**53-1)."""
    return max(0, min(int(generation), MAX_GENERATION))


def session_generation(session: object) -> int | None:
    """The vault generation of *session* as a header value, or None for a session without one."""
    generation = getattr(session, "generation", None)
    if type(generation) is not int:
        return None
    return clamp_generation(generation)


def observation(view: View, witness_file: View | None = None) -> Observation | None:
    """What *view* publishes: its own format-2 header, else the matching *witness_file*, else None.

    A witness file counts only when it is format 2, holds no records, and names the same device,
    epoch and counter as the format-1 *view* (a file left from an older write is ignored).
    """
    device_id = view.header["device_id"]
    if view.format == FORMAT_WITNESS:
        return Observation(device_id, view.vault_generation, view.witness)
    if witness_file is None or witness_file.format != FORMAT_WITNESS or witness_file.states:
        return None
    for name in ("group_id", "device_id", "epoch", "counter"):
        if witness_file.header[name] != view.header[name]:
            return None
    return Observation(device_id, witness_file.vault_generation, witness_file.witness)


#: A witness of this vault more than this far above its own generation is ignored (``witness-implausible``).
MAX_WITNESS_JUMP = 10_000


def check(own_id: str, own_generation: int, observations: Iterable[Observation],
          peer_generations: Mapping[str, int], rollback_suspected: int) -> WitnessResult:
    """Apply the rules of the module docstring; returns the issues and the updated state."""
    remembered = dict(peer_generations)
    suspected = int(rollback_suspected)
    issues: list[SyncIssue] = []
    capable: set[str] = set()
    for obs in observations:
        if obs.peer_id == own_id:
            continue
        capable.add(obs.peer_id)
        last = remembered.get(obs.peer_id)
        if last is not None and obs.vault_generation < last:
            issues.append(SyncIssue("peer-vault-rollback", obs.peer_id))
        else:
            remembered[obs.peer_id] = obs.vault_generation
        seen_of_us = obs.witness.get(own_id)
        if seen_of_us is not None and seen_of_us > own_generation + MAX_WITNESS_JUMP:
            # Far above anything this vault could have reached: a forged witness (a group-key holder could
            # otherwise make the alarm sticky with 2**53-1).  Reported, never remembered.
            issues.append(SyncIssue("witness-implausible", obs.peer_id))
        elif seen_of_us is not None and seen_of_us > own_generation:
            suspected = max(suspected, seen_of_us)
    if suspected > 0:
        issues.append(SyncIssue("vault-rollback", ""))
    return WitnessResult(tuple(issues), remembered, suspected, frozenset(capable))


def own_witness(peer_generations: Mapping[str, int], members: Iterable[str], own_id: str) -> dict[str, int]:
    """The witness this device publishes: remembered generations of current members only, at most 64."""
    keep = {m for m in members if m != own_id and is_valid_id(m)}
    picked = {d: clamp_generation(g) for d, g in peer_generations.items() if d in keep}
    return dict(sorted(picked.items())[:MAX_WITNESS])


def prune(peer_generations: Mapping[str, int], keep: Iterable[str]) -> dict[str, int]:
    """*peer_generations* limited to the ids in *keep*, at most 64 entries (sorted by id)."""
    keep = set(keep)
    return dict(sorted((d, g) for d, g in peer_generations.items() if d in keep)[:MAX_WITNESS])


__all__ = ["MAX_GENERATION", "Observation", "WitnessResult", "check", "clamp_generation", "observation",
           "own_witness", "prune", "session_generation"]
