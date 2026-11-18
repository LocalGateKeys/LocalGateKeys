"""Camera unlock active challenge: random head movements checked from YuNet's five landmarks.

Synthetic landmark sequences only; no camera, no models, no vault data.
"""
from __future__ import annotations

import math
import random

import pytest

from localvault.app import face_capture
from localvault.app.face_capture import (
    CHALLENGE_MOVES,
    CHALLENGE_STEP_SECONDS,
    ActiveChallenge,
    FaceCapture,
    head_pose,
)
from localvault.face_models import FaceObservation
from localvault.face_unlock import FaceError

FRONT_PITCH = 0.6  # nose drop / mouth drop for a frontal synthetic face
STEP = 0.1  # seconds between frames (about 10 frames a second)


def landmarks(yaw=0.0, pitch=FRONT_PITCH, *, roll=0.0, squash_x=1.0, squash_y=1.0, size=80.0,
              cx=320.0, cy=220.0):
    """Five YuNet points (right eye, left eye, nose, right mouth, left mouth) in image pixels.

    ``yaw`` and ``pitch`` are the ratios head_pose reports; ``roll`` turns the whole face in
    the image plane and ``squash_*`` foreshortens it like a flat photo tilted away."""
    points = [(-0.5, 0.0), (0.5, 0.0), (yaw, pitch * 1.2), (-0.4, 1.2), (0.4, 1.2)]
    cos, sin = math.cos(roll), math.sin(roll)
    out = []
    for x, y in points:
        x, y = x * squash_x, y * squash_y
        out.append((cx + size * (x * cos - y * sin), cy + size * (x * sin + y * cos)))
    return tuple(out)


POSES = {"left": (-0.2, FRONT_PITCH), "right": (0.2, FRONT_PITCH), "up": (0.0, FRONT_PITCH - 0.12)}


class Fixed:
    """A random source that returns the listed picks in order, then the first option."""

    def __init__(self, *picks):
        self.picks = list(picks)

    def choice(self, options):
        if not self.picks:
            return options[0]
        wanted = self.picks.pop(0)
        assert wanted in options
        return wanted


def frames_for(moves, start=0.0, *, front=4, hold=3, back=3):
    """Timed landmark frames of an honest user doing ``moves`` from a frontal start."""
    out, now = [], start
    for _ in range(front):
        out.append((now, landmarks()))
        now += STEP
    for move in moves:
        for _ in range(hold):
            out.append((now, landmarks(*POSES[move])))
            now += STEP
        for _ in range(back):
            out.append((now, landmarks()))
            now += STEP
    return out


def play(challenge, frames, matched=True):
    return any([challenge.update(points, now, matched=matched) for now, points in frames])


# ------------------------------------------------------------------ head pose
def test_head_pose_reads_yaw_and_pitch_and_ignores_roll():
    yaw, pitch = head_pose(landmarks(0.15, 0.5))
    assert yaw == pytest.approx(0.15) and pitch == pytest.approx(0.5)
    rolled = head_pose(landmarks(0.0, FRONT_PITCH, roll=0.5))
    assert rolled[0] == pytest.approx(0.0, abs=1e-9) and rolled[1] == pytest.approx(FRONT_PITCH)


def test_head_pose_rejects_missing_or_degenerate_points():
    assert head_pose(None) is None
    assert head_pose(((0, 0),) * 5) is None
    assert head_pose(((0, 0), (1, 0))) is None
    # mouth above the eyes: not a face the check can use
    assert head_pose(((0, 0), (40, 0), (20, -10), (5, -30), (35, -30))) is None


# ------------------------------------------------------------------ challenge
def test_default_random_source_is_the_os_csprng():
    assert isinstance(ActiveChallenge().rng, random.SystemRandom)


def test_challenge_is_two_different_moves():
    for _ in range(50):
        challenge = ActiveChallenge()
        assert len(challenge.moves) == 2 and challenge.moves[0] != challenge.moves[1]
        assert set(challenge.moves) <= set(CHALLENGE_MOVES)


def test_correct_movement_passes():
    challenge = ActiveChallenge(rng=Fixed(("left", "up")))
    assert challenge.prompt == "faceCapture.challengeFaceCamera"
    assert play(challenge, frames_for(["left", "up"])) is True
    assert challenge.completed and challenge.failures == 0 and challenge.progress == 1.0


def test_every_move_pair_passes_when_followed():
    for moves in [(a, b) for a in CHALLENGE_MOVES for b in CHALLENGE_MOVES if a != b]:
        challenge = ActiveChallenge(rng=Fixed(moves))
        assert play(challenge, frames_for(moves)), moves


def test_prompts_follow_the_steps():
    challenge = ActiveChallenge(rng=Fixed(("right", "left")))
    prompts = []
    for now, points in frames_for(["right", "left"]):
        prompts.append(challenge.prompt)
        challenge.update(points, now)
    assert "faceCapture.challengeTurnRight" in prompts and "faceCapture.challengeTurnLeft" in prompts
    assert prompts.index("faceCapture.challengeTurnRight") < prompts.index("faceCapture.challengeTurnLeft")
    assert challenge.prompt == ""


def test_honest_modest_turn_with_jitter_passes():
    rng = random.Random(7)  # noqa: S311 - jitter only; the challenge itself is fixed
    challenge = ActiveChallenge(rng=Fixed(("right", "up")))
    now, done = 0.0, False
    plan = [(0.0, FRONT_PITCH)] * 5 + [(0.15, FRONT_PITCH)] * 4 + [(0.0, FRONT_PITCH)] * 4 \
        + [(0.0, FRONT_PITCH - 0.09)] * 4
    for yaw, pitch in plan:
        done = challenge.update(landmarks(yaw + rng.uniform(-0.015, 0.015), pitch + rng.uniform(-0.01, 0.01)), now)
        now += STEP
    assert done


def test_wrong_direction_fails_and_draws_a_new_challenge():
    challenge = ActiveChallenge(rng=Fixed(("left", "up"), ("right", "up")))
    assert play(challenge, frames_for(["right"], back=0)) is False
    assert not challenge.completed and challenge.failures == 1 and challenge.missed
    assert challenge.moves == ("right", "up") and challenge.prompt == "faceCapture.challengeFaceCamera"


def test_diagonal_movement_does_not_answer_two_directions_at_once():
    challenge = ActiveChallenge(rng=Fixed(("left", "up"), ("right", "left")))
    frames = [(i * STEP, landmarks()) for i in range(4)]
    frames += [(0.4 + i * STEP, landmarks(-0.2, FRONT_PITCH - 0.12)) for i in range(4)]
    assert play(challenge, frames) is False
    assert challenge.failures == 1


def test_static_face_fails_and_never_completes():
    challenge = ActiveChallenge(rng=Fixed(("left", "right"), ("up", "left"), ("right", "up"), ("left", "up")))
    frames = [(i * STEP, landmarks()) for i in range(int(3 * CHALLENGE_STEP_SECONDS / STEP) + 5)]
    assert play(challenge, frames) is False
    assert challenge.failures >= 2 and challenge.done_steps == 0


def test_tilted_or_rotated_photo_does_not_count_as_a_head_turn():
    challenge = ActiveChallenge(rng=Fixed(("left", "up"), ("right", "left")))
    frames = [(i * STEP, landmarks()) for i in range(4)]
    # A flat print swung about its vertical axis, tipped back, then rotated in the image plane.
    frames += [(0.4 + i * STEP, landmarks(squash_x=0.6)) for i in range(5)]
    frames += [(0.9 + i * STEP, landmarks(squash_y=0.6)) for i in range(5)]
    frames += [(1.4 + i * STEP, landmarks(roll=0.6)) for i in range(5)]
    assert play(challenge, frames) is False
    assert challenge.done_steps == 0 and challenge.failures == 0


def test_replay_of_a_passing_sequence_fails_against_a_different_challenge():
    recording = frames_for(["left", "up"])
    assert play(ActiveChallenge(rng=Fixed(("left", "up"))), recording)
    for other in [("right", "up"), ("up", "left"), ("left", "right"), ("up", "right")]:
        assert play(ActiveChallenge(rng=Fixed(other, ("right", "left"))), recording) is False, other


def test_recording_that_sweeps_every_direction_fails():
    sweep = frames_for(["left", "right", "up", "left", "up", "right"])
    for moves in [("right", "left"), ("up", "left"), ("left", "up")]:
        challenge = ActiveChallenge(rng=Fixed(moves, ("up", "right"), ("right", "up"), ("left", "right")))
        assert play(challenge, sweep) is False, moves


def test_timeout_draws_a_new_and_different_challenge():
    challenge = ActiveChallenge(rng=Fixed(("left", "up"), ("up", "right")))
    play(challenge, [(i * STEP, landmarks()) for i in range(4)])
    assert challenge.prompt == "faceCapture.challengeTurnLeft"
    challenge.update(landmarks(), 0.3 + CHALLENGE_STEP_SECONDS + 0.1)
    assert challenge.failures == 1 and challenge.moves == ("up", "right")
    assert challenge.prompt == "faceCapture.challengeFaceCamera"


def test_timeout_never_redraws_the_same_sequence():
    for _ in range(40):
        challenge = ActiveChallenge()
        before = challenge.moves
        play(challenge, [(i * STEP, landmarks()) for i in range(4)])
        challenge.update(landmarks(), 100.0)
        assert challenge.failures == 1 and challenge.moves != before


def test_timeout_also_fires_while_the_face_is_lost():
    challenge = ActiveChallenge(rng=Fixed(("left", "up"), ("up", "right")))
    play(challenge, [(i * STEP, landmarks()) for i in range(4)])
    challenge.update(None, 0.5)
    challenge.update(None, 0.5 + CHALLENGE_STEP_SECONDS)
    assert challenge.moves == ("up", "right") and challenge.done_steps == 0


def test_a_long_gap_without_a_face_restarts_the_challenge():
    challenge = ActiveChallenge(rng=Fixed(("left", "up"), ("up", "right")))
    play(challenge, frames_for(["left"]))
    assert challenge.done_steps == 1
    challenge.update(None, 5.0)
    assert challenge.done_steps == 0 and challenge.moves == ("up", "right")
    assert challenge.failures == 1  # a move was shown: the redraw is a spent try


def test_baseline_needs_the_owner_and_a_frontal_pose():
    challenge = ActiveChallenge(rng=Fixed(("left", "up")))
    play(challenge, [(i * STEP, landmarks()) for i in range(10)], matched=False)
    assert challenge.prompt == "faceCapture.challengeFaceCamera"
    play(challenge, [(1 + i * STEP, landmarks(0.3)) for i in range(10)])
    assert challenge.prompt == "faceCapture.challengeFaceCamera"


def test_restart_for_a_person_change_resets_progress_and_draws_again():
    challenge = ActiveChallenge(rng=Fixed(("left", "up"), ("right", "left")))
    play(challenge, frames_for(["left"]))
    assert challenge.done_steps == 1
    challenge.restart()
    assert challenge.done_steps == 0 and challenge.progress == 0.0
    assert challenge.failures == 1  # a move was shown: the redraw is a spent try
    assert challenge.moves == ("right", "left") and challenge.prompt == "faceCapture.challengeFaceCamera"


# ------------------------------------------------------------------ in the camera loop
SIZE = 128


def unit(seed: float) -> tuple[float, ...]:
    raw = [math.sin(seed * (i + 1)) for i in range(SIZE)]
    norm = math.sqrt(sum(v * v for v in raw))
    return tuple(v / norm for v in raw)


ME, OTHER = unit(1.0), unit(2.7)


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


class Capture:
    def read(self):
        return True, object()

    def release(self):
        pass


class CV2:
    @staticmethod
    def flip(frame, axis):
        return frame


class Engine:
    """A face that follows the live prompt (``follow``), stays still, or turns into someone else."""

    def __init__(self, clock, *, follow=True, stranger_at=None, wrong=False):
        self.cv2 = CV2()
        self.clock, self.follow, self.stranger_at, self.wrong = clock, follow, stranger_at, wrong
        self.run = None
        self.n = 0

    def analyze(self, frame):
        self.n += 1
        if self.n > 2000:  # a run that never ends would hang the suite
            raise RuntimeError("the capture loop did not stop")
        self.clock.now += STEP
        feature = OTHER if self.n == self.stranger_at else ME
        pose = (0.0, FRONT_PITCH)
        target = self.run.challenge.target if (self.run and self.run.challenge) else None
        if self.follow and target:
            if self.wrong:
                target = {"left": "right", "right": "left", "up": "left"}[target]
            pose = POSES[target]
        sway = self.n % 3
        return FaceObservation(face_count=1, bbox=(200 + sway, 140, 200, 200), yaw=pose[0], scale=0.5,
                               feature=feature, landmarks=landmarks(*pose))


def make(engine, clock):
    events = []
    run = FaceCapture("verify", templates=[list(ME)] * 3, threshold=0.45, engine_factory=lambda: engine,
                      open_camera=lambda cv2, index: (Capture(), index), emit=lambda n, d: events.append((n, d)),
                      clock=clock, encode=lambda *a: None, sleep=lambda s: None)
    engine.run = run
    return run, events


def test_capture_unlocks_when_the_prompt_is_followed_and_shows_the_prompts():
    clock = Clock()
    run, events = make(Engine(clock), clock)
    assert run.run() is True
    statuses = [d["status"] for n, d in events if n == "face.status"]
    assert any(s in statuses for s in ("Turn your head to the left", "Turn your head to the right", "Look up"))
    assert statuses[-1] == "Face recognised"


def test_capture_refuses_a_still_face_and_counts_the_try():
    clock = Clock()
    run, _events = make(Engine(clock, follow=False), clock)
    with pytest.raises(FaceError) as failed:
        run.run()
    assert failed.value.face_rejected is True
    assert run.challenge.failures >= 2


def test_capture_refuses_the_wrong_direction():
    clock = Clock()
    run, events = make(Engine(clock, wrong=True), clock)
    with pytest.raises(FaceError) as failed:
        run.run()
    assert failed.value.face_rejected is True
    details = [d["detail"] for n, d in events if n == "face.status"]
    assert "That did not match the prompt. Follow the new one." in details


def test_someone_else_in_view_restarts_the_challenge(monkeypatch):
    clock = Clock()
    draws = []
    original = ActiveChallenge.restart

    def restart(self, *, failed=False):
        draws.append((self.done_steps, failed))
        original(self, failed=failed)

    monkeypatch.setattr(ActiveChallenge, "restart", restart)
    engine = Engine(clock, stranger_at=12)
    run, _events = make(engine, clock)
    assert run.run() is True
    assert draws and draws[0][1] is False  # the stranger frame restarted it, without a failure


def test_enrolment_needs_no_challenge():
    clock = Clock()
    engine = Engine(clock, follow=False)
    run = FaceCapture("enroll", engine_factory=lambda: engine, open_camera=lambda cv2, index: (Capture(), index),
                      emit=lambda n, d: None, clock=clock, encode=lambda *a: None, sleep=lambda s: None)
    engine.run = run
    assert len(run.run()) == face_capture.ENROLL_SAMPLES


# ------------------------------------------------------------------ redraw limits (one retry per run)
def test_a_long_gap_after_a_revealed_move_counts_as_a_failure():
    challenge = ActiveChallenge(rng=Fixed(("left", "up"), ("up", "right")))
    play(challenge, [(i * STEP, landmarks()) for i in range(4)])
    assert challenge.target == "left"  # the move is on screen now
    challenge.update(None, 0.5)
    challenge.update(None, 0.5 + 1.5)
    assert challenge.failures == 1 and challenge.missed and challenge.moves == ("up", "right")


def test_a_restart_before_any_move_was_shown_is_free():
    challenge = ActiveChallenge(rng=Fixed(("left", "up"), ("up", "right")))
    challenge.restart()
    assert challenge.failures == 0 and not challenge.exhausted


def test_a_restart_after_a_revealed_move_counts_as_a_failure():
    challenge = ActiveChallenge(rng=Fixed(("left", "up"), ("up", "right")))
    play(challenge, [(i * STEP, landmarks()) for i in range(4)])
    challenge.restart()  # someone else in view, or a camera switch, mid-challenge
    assert challenge.failures == 1


def test_the_challenge_is_used_up_after_two_failed_sequences():
    challenge = ActiveChallenge(rng=Fixed(("left", "up"), ("up", "right")))
    assert face_capture.CHALLENGE_MAX_FAILURES == 2
    challenge.restart(failed=True)
    assert not challenge.exhausted
    challenge.restart(failed=True)
    assert challenge.exhausted


def test_hiding_the_face_cannot_redraw_until_a_recording_matches():
    """A fixed recording of one sequence, replayed with the face hidden between tries."""
    clock = Clock()
    engine = Engine(clock, follow=False)
    run, _events = make(engine, clock)
    with pytest.raises(FaceError) as failed:
        run.run()
    assert failed.value.face_rejected is True
    assert run.challenge.failures == face_capture.CHALLENGE_MAX_FAILURES
    assert clock.now < face_capture.TIMEOUT_SECONDS  # ended by the failures, not by the time limit


class SwitchingEngine(Engine):
    """Presses "Try another camera" each time a move is on screen, never doing it."""

    def analyze(self, frame):
        observation = super().analyze(frame)
        if self.run.challenge is not None and self.run.challenge.target:
            self.run.switch_camera()
        return observation


def test_switching_camera_mid_challenge_counts_and_keeps_the_time_limit():
    clock = Clock()
    engine = SwitchingEngine(clock, follow=False)
    run, _events = make(engine, clock)
    with pytest.raises(FaceError) as failed:
        run.run()
    assert failed.value.face_rejected is True
    assert run.challenge.failures == face_capture.CHALLENGE_MAX_FAILURES


def test_switching_camera_does_not_reset_the_time_limit():
    clock = Clock()

    class Frontal(Engine):
        def analyze(self, frame):
            observation = super().analyze(frame)
            if self.n % 50 == 0:
                self.run.switch_camera()
            return FaceObservation(face_count=1, bbox=observation.bbox, yaw=0.0, scale=0.5,
                                   feature=None, landmarks=None)  # no usable face, never a move

    engine = Frontal(clock, follow=False)
    run, _events = make(engine, clock)
    with pytest.raises(FaceError):
        run.run()
    assert clock.now <= face_capture.TIMEOUT_SECONDS + 1.0
