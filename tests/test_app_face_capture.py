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


# Five landmark poses (yaw, pitch ratio) a cooperating user shows for each unlock prompt.
POSES = {None: (0.0, 0.6), "left": (-0.2, 0.6), "right": (0.2, 0.6), "up": (0.0, 0.48)}


def points(yaw, pitch, size=80.0):
    raw = [(-0.5, 0.0), (0.5, 0.0), (yaw, pitch * 1.2), (-0.4, 1.2), (0.4, 1.2)]
    return tuple((300 + size * x, 200 + size * y) for x, y in raw)


class Engine:
    """Scripted observations: a live face that sways slightly and follows the unlock prompt."""

    def __init__(self, feature=ME, usable=True):
        self.cv2 = CV2()
        self.feature = feature
        self.usable = usable
        self.n = 0
        self.run = None  # the FaceCapture whose movement prompt this face follows

    def landmarks(self):
        challenge = getattr(self.run, "challenge", None)
        return points(*POSES[challenge.target if challenge else None])

    def analyze(self, frame):
        self.n += 1
        if not self.usable:
            return FaceObservation(face_count=0, quality_reason="No face in view")
        sway = (self.n % 4) * 2
        return FaceObservation(face_count=1, bbox=(100 + sway, 100, 200, 200), yaw=0.01 * (self.n % 3),
                               scale=0.5, feature=self.feature, landmarks=self.landmarks())


def make(mode, *, engine=None, capture=None, templates=None, clock=None):
    events = []
    capture = capture or Capture()
    engine = engine or Engine()
    run = FaceCapture(mode, templates=templates or [], threshold=0.45, engine_factory=lambda: engine,
                      open_camera=lambda cv2, index: (capture, index), emit=lambda n, d: events.append((n, d)),
                      clock=clock or Clock(), encode=lambda frame, obs, progress, state: "data:image/jpeg;base64,x",
                      sleep=lambda s: None)
    engine.run = run
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
        return FaceObservation(face_count=1, bbox=obs.bbox, yaw=obs.yaw, scale=obs.scale, feature=feature,
                               landmarks=obs.landmarks)


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


def test_open_camera_stops_searching_when_cancelled():
    from localvault.app.face_capture import _open_camera
    from localvault.face_unlock import FaceCancelled

    opened = []

    class Cv:
        CAP_ANY = 0

        @staticmethod
        def VideoCapture(index, backend):
            opened.append(index)

            class Closed:
                def isOpened(self):
                    return False

                def release(self):
                    pass
            return Closed()

    stops = iter([False, True])
    try:
        _open_camera(Cv, 0, stop=lambda: next(stops))
    except FaceCancelled:
        pass
    else:
        raise AssertionError("cancel did not stop the camera search")
    assert opened == [0]


def test_open_camera_gives_up_after_time_budget():
    from localvault.app.face_capture import OPEN_CAMERA_BUDGET_SECONDS, _open_camera
    from localvault.face_unlock import FaceUnavailable

    now = [0.0]
    opened = []

    class Cv:
        CAP_ANY = 0

        @staticmethod
        def VideoCapture(index, backend):
            opened.append(index)
            now[0] += OPEN_CAMERA_BUDGET_SECONDS  # a very slow driver

            class Closed:
                def isOpened(self):
                    return False

                def release(self):
                    pass
            return Closed()

    try:
        _open_camera(Cv, 0, clock=lambda: now[0])
    except FaceUnavailable:
        pass
    else:
        raise AssertionError("expected no camera")
    assert len(opened) < 4


def test_open_camera_cancel_has_no_mode_specific_text():
    from localvault.app.face_capture import _open_camera
    from localvault.face_unlock import FaceCancelled

    class Cv:
        CAP_ANY = 0

    try:
        _open_camera(Cv, 0, stop=lambda: True)
    except FaceCancelled as exc:
        assert str(exc) == ""
    else:
        raise AssertionError("expected a cancel")


def test_switch_keeps_the_working_camera_when_no_other_opens():
    from localvault.face_unlock import FaceUnavailable
    capture = Capture()
    opens = []

    def open_camera(cv2, index):
        opens.append(index)
        if len(opens) > 1:
            raise FaceUnavailable("No usable webcam was found.")
        return capture, index

    engine = Engine()
    run = FaceCapture("verify", templates=[list(ME)], threshold=0.45, engine_factory=lambda: engine,
                      open_camera=open_camera, emit=lambda n, d: None, clock=Clock(),
                      encode=lambda *a: None, sleep=lambda s: None)
    engine.run = run
    run.switch_camera()
    assert run.run() is True
    assert opens == [0, 1]


def test_cancel_after_seeing_someone_else_counts_as_rejected():
    from localvault.face_unlock import FaceCancelled
    engine = Engine(feature=OTHER)
    original = engine.analyze
    holder = {}

    def analyze(frame):
        if engine.n >= 6:
            holder["run"].cancel()
        return original(frame)

    engine.analyze = analyze
    run, _events, _capture = make("verify", engine=engine, templates=[list(ME)])
    holder["run"] = run
    with pytest.raises(FaceCancelled) as cancelled:
        run.run()
    assert cancelled.value.face_rejected is True


def test_plain_cancel_is_not_a_rejection():
    from localvault.face_unlock import FaceCancelled
    run, _events, _capture = make("verify", engine=Engine(usable=False), templates=[list(ME)])
    run.cancel()
    with pytest.raises(FaceCancelled) as cancelled:
        run.run()
    assert cancelled.value.face_rejected is False


def _blocked_start(monkeypatch=None, **kwargs):
    """A verify run whose camera open blocks, like a driver stuck inside one call."""
    import threading

    gate, entered, capture = threading.Event(), threading.Event(), Capture()

    def slow_open(cv2, index):
        entered.set()
        gate.wait(10)
        return capture, index

    events = []
    run = FaceCapture("verify", templates=[list(ME)], engine_factory=lambda: Engine(),
                      emit=lambda n, d: events.append((n, d)), open_camera=slow_open, clock=Clock(),
                      encode=lambda *a: None, sleep=lambda s: None, **kwargs)
    return run, gate, entered, capture, events


def test_cancel_ends_a_run_whose_camera_open_is_blocked_and_frees_the_late_camera():
    import threading
    import time

    from localvault.face_unlock import FaceCancelled

    run, gate, entered, capture, events = _blocked_start()
    released = threading.Event()
    capture.release = released.set
    outcome = []

    def go():
        try:
            run.run()
        except Exception as exc:  # noqa: BLE001
            outcome.append(exc)

    worker = threading.Thread(target=go, daemon=True)
    worker.start()
    assert entered.wait(5)
    started = time.monotonic()
    run.cancel()
    worker.join(5)
    assert not worker.is_alive() and time.monotonic() - started < 2
    assert isinstance(outcome[0], FaceCancelled) and str(outcome[0])
    assert events[-1][1]["state"] == "cancelled"
    assert not released.is_set()
    gate.set()  # the driver call returns after the run is over
    assert released.wait(5)


def test_a_blocked_camera_open_gives_up_at_the_start_time_limit(monkeypatch):
    from localvault.app import face_capture
    from localvault.face_unlock import FaceUnavailable

    monkeypatch.setattr(face_capture, "START_TIMEOUT_SECONDS", 0.2)
    run, gate, _entered, _capture, events = _blocked_start()
    with pytest.raises(FaceUnavailable):
        run.run()
    assert events[-1][1]["state"] == "failed"
    gate.set()
