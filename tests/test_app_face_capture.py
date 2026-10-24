"""Stage 4b: the Tk-free camera loop (enrolment and verification) with a fake engine and camera."""
from __future__ import annotations

import math

import pytest

from localvault.app.face_capture import FaceCapture
from localvault.face_models import FaceObservation
from localvault.face_unlock import FaceCancelled, FaceError

SIZE = 128


def unit(seed: float) -> tuple[float, ...]:
    raw = [math.sin(seed * (i + 1)) for i in range(SIZE)]
    norm = math.sqrt(sum(v * v for v in raw))
    return tuple(v / norm for v in raw)


ME = unit(1.0)
OTHER = unit(2.7)


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


class Capture:
    def __init__(self, frames=True):
        self.frames = frames
        self.released = False

    def read(self):
        return (True, object()) if self.frames else (False, None)

    def release(self):
        self.released = True


class CV2:
    @staticmethod
    def flip(frame, axis):
        return frame


class Engine:
    """Scripted observations: a live face that sways slightly."""

    def __init__(self, feature=ME, usable=True):
        self.cv2 = CV2()
        self.feature = feature
        self.usable = usable
        self.n = 0

    def analyze(self, frame):
        self.n += 1
        if not self.usable:
            return FaceObservation(face_count=0, quality_reason="No face in view")
        sway = (self.n % 4) * 2
        return FaceObservation(face_count=1, bbox=(100 + sway, 100, 200, 200), yaw=0.01 * (self.n % 3),
                               scale=0.5, feature=self.feature)


def make(mode, *, engine=None, capture=None, templates=None, clock=None):
    events = []
    capture = capture or Capture()
    run = FaceCapture(mode, templates=templates or [], threshold=0.45, engine_factory=lambda: engine or Engine(),
                      open_camera=lambda cv2, index: (capture, index), emit=lambda n, d: events.append((n, d)),
                      clock=clock or Clock(), encode=lambda frame, obs, progress, state: "data:image/jpeg;base64,x",
                      sleep=lambda s: None)
    return run, events, capture


def test_enrol_collects_eight_samples_after_liveness():
    run, events, capture = make("enroll")
    samples = run.run()
    assert len(samples) == 8 and all(len(s) == SIZE for s in samples)
    assert capture.released
    statuses = [d["status"] for n, d in events if n == "face.status"]
    assert statuses[-1] == "Face set up"


def test_verify_accepts_the_enrolled_face():
    run, events, capture = make("verify", templates=[list(ME)])
    assert run.run() is True
    assert [d["status"] for n, d in events if n == "face.status"][-1] == "Face recognised"
    assert capture.released


def test_verify_rejects_another_face_after_thirty_seconds():
    clock = Clock()
    engine = Engine(feature=OTHER)
    original = engine.analyze

    def analyze(frame):
        clock.now += 0.5
        return original(frame)

    engine.analyze = analyze
    run, events, capture = make("verify", engine=engine, templates=[list(ME)], clock=clock)
    with pytest.raises(FaceError) as failed:
        run.run()
    assert str(failed.value).startswith("Face not recognised in time.")
    assert "Face not recognised" in [d["status"] for n, d in events if n == "face.status"]
    assert capture.released


def test_stalled_camera_is_an_error():
    clock = Clock()
    capture = Capture(frames=False)
    run, _events, _ = make("verify", capture=capture, templates=[list(ME)], clock=clock)
    original = capture.read

    def read():
        clock.now += 1.0
        return original()

    capture.read = read
    with pytest.raises(FaceError) as failed:
        run.run()
    assert str(failed.value) == "The webcam stopped returning images. Close other camera apps and retry."
    assert capture.released


def test_cancel_stops_and_releases():
    engine = Engine(usable=False)
    run, events, capture = make("verify", engine=engine, templates=[list(ME)])
    original = engine.analyze

    def analyze(frame):
        run.cancel()
        return original(frame)

    engine.analyze = analyze
    with pytest.raises(FaceCancelled):
        run.run()
    assert capture.released
    frames_after = [n for n, _d in events if n == "face.frame"]
    assert len(frames_after) <= 1


def test_frames_are_throttled():
    clock = Clock()
    engine = Engine()
    original = engine.analyze

    def analyze(frame):
        clock.now += 0.02
        return original(frame)

    engine.analyze = analyze
    run, events, _ = make("enroll", engine=engine, clock=clock)
    run.run()
    frames = [n for n, _d in events if n == "face.frame"]
    analysed = engine.n
    assert 0 < len(frames) < analysed


def test_missing_camera_is_unavailable_not_a_mismatch():
    from localvault.face_unlock import FaceUnavailable

    def no_camera(cv2, index):
        from localvault.app.face_capture import _open_camera
        raise FaceUnavailable("No usable webcam was found.")

    run = FaceCapture("verify", templates=[list(ME)], engine_factory=lambda: Engine(), emit=lambda n, d: None,
                      open_camera=no_camera, clock=Clock(), encode=lambda *a: None, sleep=lambda s: None)
    with pytest.raises(FaceUnavailable):
        run.run()


def test_stalled_camera_is_unavailable():
    from localvault.face_unlock import FaceUnavailable
    clock = Clock()
    capture = Capture(frames=False)
    run, _e, _ = make("verify", capture=capture, templates=[list(ME)], clock=clock)
    original = capture.read
    capture.read = lambda: (setattr(clock, "now", clock.now + 1.0), original())[1]
    with pytest.raises(FaceUnavailable):
        run.run()


# ---------------------------------------------------------- identity hardening
def near(base, seed, amount):
    noise = unit(seed)
    raw = [b + amount * n for b, n in zip(base, noise)]
    norm = math.sqrt(sum(v * v for v in raw))
    return tuple(v / norm for v in raw)


class Script(Engine):
    """Plays a fixed list of features, then repeats the last one."""

    def __init__(self, features):
        super().__init__()
        self.features = list(features)

    def analyze(self, frame):
        obs = super().analyze(frame)
        feature = self.features[min(self.n - 1, len(self.features) - 1)]
        return FaceObservation(face_count=1, bbox=obs.bbox, yaw=obs.yaw, scale=obs.scale, feature=feature)


def test_enrolment_never_mixes_two_people():
    from localvault.face_models import best_match
    features = [ME if i % 2 else OTHER for i in range(400)]
    run, _e, _ = make("enroll", engine=Script(features))
    try:
        samples = run.run()
    except FaceError:
        return  # refusing to finish is fine; mixing is not
    first = samples[0]
    assert all(best_match(s, [first]) > 0.9 for s in samples)


def test_alternating_owner_and_stranger_never_unlocks():
    clock = Clock()
    engine = Script([ME if i % 2 else OTHER for i in range(400)])
    original = engine.analyze

    def analyze(frame):
        clock.now += 0.2
        return original(frame)

    engine.analyze = analyze
    run, _e, _ = make("verify", engine=engine, templates=[list(ME)] * 8, clock=clock)
    with pytest.raises(FaceError):
        run.run()


def test_lookalike_matching_one_template_only_is_not_enough():
    clock = Clock()
    owner = [list(near(ME, 3 + i, 0.6)) for i in range(8)]
    lucky = owner[0]
    engine = Script([tuple(lucky)] * 400)
    original = engine.analyze

    def analyze(frame):
        clock.now += 0.2
        return original(frame)

    engine.analyze = analyze
    templates = [lucky] + [list(unit(9 + i)) for i in range(7)]  # seven unrelated templates
    run, _e, _ = make("verify", engine=engine, templates=templates, clock=clock)
    with pytest.raises(FaceError):
        run.run()


def test_the_owner_still_unlocks_with_natural_variation():
    owner = [list(near(ME, 3 + i, 0.25)) for i in range(8)]
    frames = [near(ME, 50 + i, 0.25) for i in range(60)]
    run, _e, _ = make("verify", engine=Script(frames), templates=owner)
    assert run.run() is True


def test_enrolment_rejects_a_lookalike_mixed_in():
    from localvault.face_models import best_match
    lookalike = near(ME, 77, 2.4)
    assert 0.32 < best_match(lookalike, [list(ME)]) < 0.5
    features = [ME if i % 2 else lookalike for i in range(400)]
    run, _e, _ = make("enroll", engine=Script(features))
    try:
        samples = run.run()
    except FaceError:
        return
    assert all(best_match(s, [list(ME)]) > 0.9 for s in samples)
