"""Camera enrolment and verification without Tk, for the WebView UI.

The per-frame logic of ``face_ui._CameraDialog`` (passive liveness, 8 enrolment
samples, 4 matching frames out of the last 7) runs on a worker thread. Unlock also
asks for random head movements (``ActiveChallenge``) shown as the status text. The page
gets ``face.status`` updates and throttled ``face.frame`` previews: small JPEG
data URLs that exist only in memory and are never written to disk.
"""
from __future__ import annotations

import base64
import functools
import math
import secrets
import sys
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

from ..face_models import DEFAULT_MATCH_THRESHOLD, FaceModelError, FaceObservation
from ..face_unlock import FaceCancelled, FaceError, FaceUnavailable
from ..i18n import t

ENROLL_SAMPLES = 8
# Identity rules (shared with the classic window's camera dialog):
# - setup: every new sample must look like EVERY earlier sample, so a second person
#   can never be mixed into the enrolled face;
# - unlock: VERIFY_RUN consecutive frames must each match at least TEMPLATE_AGREEMENT
#   of the enrolled samples; a frame that clearly shows someone else restarts the
#   whole check, liveness included, so frames from two people never add up.
ENROLL_SAME_PERSON = 0.50
VERIFY_RUN = 5
TEMPLATE_AGREEMENT = 3
STRANGER_SCORE = 0.30
# Kept for callers that still read them.
VERIFY_WINDOW = VERIFY_RUN
VERIFY_HITS = VERIFY_RUN


def same_person(feature: Sequence[float], samples: Sequence[Sequence[float]]) -> bool:
    """Setup: a new sample joins only if it matches every sample already taken."""
    from ..face_models import cosine_score

    return all(cosine_score(feature, sample) >= ENROLL_SAME_PERSON for sample in samples)


def frame_verdict(feature: Sequence[float], templates: Sequence[Sequence[float]], threshold: float) -> str:
    """Unlock: "match", "stranger" (clearly someone else) or "unsure" for one frame."""
    from ..face_models import cosine_score

    scores = [cosine_score(feature, template) for template in templates] if feature else []
    if not scores:
        return "unsure"
    needed = min(TEMPLATE_AGREEMENT, len(scores))
    if sum(1 for score in scores if score >= threshold) >= needed:
        return "match"
    if max(scores) < STRANGER_SCORE:
        return "stranger"
    return "unsure"
TIMEOUT_SECONDS = 30
STALL_SECONDS = 3
FRAME_INTERVAL = 0.12  # about 8 preview frames a second
PREVIEW_PIXELS = 240
PRIVACY = "cameraView.noUpload"
TIMEOUT_TEXT = ("faceCapture.faceNotRecognisedInTime")
STALLED_TEXT = "qrImport.theWebcamStoppedReturningImages2"
CRASHED_TEXT = "faceCapture.theCameraVerificationWindowStopped"
CANCELLED_TEXT = "faceCapture.cameraVerificationWasCancelledYour"


@dataclass
class PassiveLiveness:
    """Face ID-style passive check: just look at the camera.

    No prompted movement is needed. A live face always shows small natural
    micro-motion (head sway, landmark jitter) across a short run of frames; a
    frozen feed or a photo on a stand does not. The check completes once enough
    consecutive usable frames show that motion without large jumps.

    An RGB webcam has no depth or IR sensor, so this blocks a static image or
    frozen frame but is not a hardware anti-spoof guarantee like Windows Hello.
    """

    frames_needed: int = 6
    min_motion: float = 0.004
    max_motion: float = 0.35
    samples: list[tuple[float, float, float, float]] = field(default_factory=list)
    completed: bool = False

    def reset(self) -> None:
        if not self.completed:
            self.samples.clear()

    @property
    def progress(self) -> float:
        return 1.0 if self.completed else min(1.0, len(self.samples) / self.frames_needed)

    def update(self, observation: FaceObservation) -> bool:
        if self.completed:
            return True
        if not observation.usable or not observation.bbox:
            self.reset()
            return False
        x, y, w, h = observation.bbox
        size = float(max(w, h, 1))
        # Normalise by face size so the thresholds do not depend on distance.
        self.samples.append(((x + w / 2.0) / size, (y + h / 2.0) / size,
                             float(observation.yaw), float(observation.scale) * 10.0))
        self.samples = self.samples[-self.frames_needed:]
        if len(self.samples) < self.frames_needed:
            return False
        motion = max(max(axis) - min(axis) for axis in zip(*self.samples))
        if motion > self.max_motion:
            # A big jump (face swapped in/out, camera bumped): start again.
            self.samples = self.samples[-1:]
            return False
        if motion >= self.min_motion:
            self.completed = True
        return self.completed


# Active challenge (unlock only). The user is asked for random head movements, so a
# photo or a video recorded earlier cannot know what to show. The frame is mirrored
# before analysis, so "left" is the user's own left, as in the preview.
CHALLENGE_MOVES = ("left", "right", "up")
CHALLENGE_STEPS = 2
CHALLENGE_STEP_SECONDS = 6.0  # per movement, including the return to the camera before it
CHALLENGE_GAP_SECONDS = 1.0  # no face for longer than this starts a new challenge
# Failed sequences allowed in one run (the first try plus one retry). Every new sequence
# drawn after a move was shown counts, whatever the reason, so hiding the face or
# switching camera cannot redraw until a fixed recording happens to match.
CHALLENGE_MAX_FAILURES = 2
YAW_TURN = 0.10  # nose shift along the eye line / eye distance: about 10-12 degrees
PITCH_TURN = 0.06  # change of nose drop / mouth drop: about 10-12 degrees up
FRONTAL_YAW = 0.12  # the challenge starts only from a roughly frontal pose
FRONTAL_FRAMES = 3
HOLD_FRAMES = 2  # a pose counts (right or wrong) after this many frames in a row
CENTRE_SHARE = 0.7  # "back at the camera" means within 70 % of a turn
CHALLENGE_PROMPTS = {
    "left": "faceCapture.challengeTurnLeft",
    "right": "faceCapture.challengeTurnRight",
    "up": "faceCapture.challengeLookUp",
}
CHALLENGE_FRONT = "faceCapture.challengeFaceCamera"
CHALLENGE_RETRY = "faceCapture.challengeRetry"
CHALLENGE_FAILED = "faceCapture.challengeFailed"


def head_pose(landmarks: Sequence[Sequence[float]] | None) -> tuple[float, float] | None:
    """(yaw, pitch) from YuNet's five points, measured in the face's own frame.

    yaw: nose offset along the eye line divided by the eye distance (negative = the
    user's left in a mirrored frame). pitch: nose drop below the eye line divided by
    the mouth drop (smaller = looking up). Both are ratios inside the face, so turning
    a flat photo in the image plane, or tilting it away, barely changes them; only a
    real 3-D head (nose in front of the eyes and mouth) moves the nose against them."""
    if not landmarks or len(landmarks) < 5:
        return None
    try:
        points = [(float(p[0]), float(p[1])) for p in landmarks[:5]]
    except (TypeError, ValueError, IndexError):
        return None
    if not all(math.isfinite(value) for point in points for value in point):
        return None
    first, second = sorted(points[:2])
    nose = points[2]
    ex, ey = second[0] - first[0], second[1] - first[1]
    distance = math.hypot(ex, ey)
    if distance < 1.0:
        return None
    ux, uy = ex / distance, ey / distance
    px, py = -uy, ux  # perpendicular, pointing down the face
    mid_x, mid_y = (first[0] + second[0]) / 2.0, (first[1] + second[1]) / 2.0
    mouth_x = (points[3][0] + points[4][0]) / 2.0 - mid_x
    mouth_y = (points[3][1] + points[4][1]) / 2.0 - mid_y
    mouth_drop = mouth_x * px + mouth_y * py
    if mouth_drop < 0.3 * distance:
        return None
    nx, ny = nose[0] - mid_x, nose[1] - mid_y
    return (nx * ux + ny * uy) / distance, (nx * px + ny * py) / mouth_drop


def _challenge_sequences(steps: int) -> list[tuple[str, ...]]:
    sequences: list[tuple[str, ...]] = [()]
    for _ in range(steps):
        sequences = [seq + (move,) for seq in sequences for move in CHALLENGE_MOVES if not seq or seq[-1] != move]
    return sequences


@dataclass
class ActiveChallenge:
    """Random head movements that must be followed in order within a short time.

    Pure logic: feed it each frame's landmarks, the time, and whether the frame
    matched the owner. It starts from a steady frontal pose of the owner, then asks
    for each move in turn; the asked move must be held for HOLD_FRAMES frames, and a
    clear move in any other direction first fails the challenge. A failure or a
    timeout draws a new sequence (never the one just failed) and counts in
    ``failures``. ``rng`` is the OS CSPRNG unless a test passes another source.
    """

    rng: Any = field(default_factory=secrets.SystemRandom)
    steps: int = CHALLENGE_STEPS
    step_seconds: float = CHALLENGE_STEP_SECONDS
    moves: tuple[str, ...] = ()
    done_steps: int = 0
    phase: str = "frontal"  # frontal | move | centre | done
    failures: int = 0
    missed: bool = False  # the last attempt failed: the page says a new prompt follows
    _baseline: list[tuple[float, float]] = field(default_factory=list)
    _base: tuple[float, float] = (0.0, 0.0)
    _hold: int = 0
    _wrong: int = 0
    _deadline: float | None = None
    _last_seen: float | None = None

    def __post_init__(self) -> None:
        self._draw()

    def _draw(self) -> None:
        options = [seq for seq in _challenge_sequences(self.steps) if seq != self.moves]
        self.moves = tuple(self.rng.choice(options))
        self.done_steps = 0
        self.phase = "frontal"
        self._baseline.clear()
        self._hold = self._wrong = 0
        self._deadline = None
        self._last_seen = None

    def restart(self, *, failed: bool = False) -> None:
        """Start over with a new sequence (someone else in view, camera switch, failure).

        Once a move was shown, any new sequence counts as a failure: the reason does not
        matter, as each redraw is another chance for a fixed recording to match."""
        if failed or self.phase != "frontal":
            self.failures += 1
            self.missed = True
        self._draw()

    @property
    def exhausted(self) -> bool:
        """No more sequences in this run: the unlock attempt has failed."""
        return self.failures >= CHALLENGE_MAX_FAILURES

    @property
    def completed(self) -> bool:
        return self.phase == "done"

    @property
    def progress(self) -> float:
        return self.done_steps / float(self.steps)

    @property
    def target(self) -> str | None:
        """The move asked for right now, or None while the user should face the camera."""
        return self.moves[self.done_steps] if self.phase == "move" else None

    @property
    def prompt(self) -> str:
        """i18n key of what the user should do now ("" once completed)."""
        if self.phase == "done":
            return ""
        return CHALLENGE_PROMPTS[self.moves[self.done_steps]] if self.phase == "move" else CHALLENGE_FRONT

    def update(self, landmarks: Sequence[Sequence[float]] | None, now: float, matched: bool = True) -> bool:
        if self.phase == "done":
            return True
        if self._deadline is not None and now > self._deadline:
            self.restart(failed=True)  # too slow: a new, different sequence
            return False
        pose = head_pose(landmarks)
        if pose is None:
            if self.phase != "frontal" and self._last_seen is not None and now - self._last_seen > CHALLENGE_GAP_SECONDS:
                self.restart()  # the face left the view mid-challenge (counts as a failure)
            return False
        self._last_seen = now
        yaw, pitch = pose
        if self.phase == "frontal":
            if not matched or abs(yaw) > FRONTAL_YAW:
                self._baseline.clear()
                return False
            self._baseline.append(pose)
            del self._baseline[:-FRONTAL_FRAMES]
            if len(self._baseline) == FRONTAL_FRAMES:
                yaws, pitches = zip(*self._baseline, strict=True)
                if max(yaws) - min(yaws) <= YAW_TURN / 2 and max(pitches) - min(pitches) <= PITCH_TURN / 2:
                    self._base = (sum(yaws) / FRONTAL_FRAMES, sum(pitches) / FRONTAL_FRAMES)
                    self.phase = "move"
                    self._hold = self._wrong = 0
                    self._deadline = now + self.step_seconds
            return False
        d_yaw, d_pitch = yaw - self._base[0], pitch - self._base[1]
        if self.phase == "centre":
            if abs(d_yaw) <= YAW_TURN * CENTRE_SHARE and abs(d_pitch) <= PITCH_TURN * CENTRE_SHARE:
                self._hold += 1
                if self._hold >= HOLD_FRAMES:
                    self.phase, self._hold, self._wrong = "move", 0, 0
            else:
                self._hold = 0
            return False
        reached = {"left": d_yaw <= -YAW_TURN, "right": d_yaw >= YAW_TURN, "up": d_pitch <= -PITCH_TURN}
        asked = self.moves[self.done_steps]
        if any(hit for move, hit in reached.items() if move != asked):
            self._hold = 0
            self._wrong += 1
            if self._wrong >= HOLD_FRAMES:
                self.restart(failed=True)
            return False
        self._wrong = 0
        if not reached[asked]:
            self._hold = 0
            return False
        self._hold += 1
        if self._hold < HOLD_FRAMES:
            return False
        self.done_steps += 1
        self.missed = False
        self._hold = 0
        if self.done_steps >= self.steps:
            self.phase, self._deadline = "done", None
            return True
        self.phase = "centre"
        self._deadline = now + self.step_seconds
        return False


def _camera_backends(cv2: Any) -> list[int]:
    values: list[int] = []
    if sys.platform == "win32":
        for name in ("CAP_DSHOW", "CAP_MSMF"):
            value = getattr(cv2, name, None)
            if isinstance(value, int) and value not in values:
                values.append(value)
    any_backend = int(getattr(cv2, "CAP_ANY", 0))
    if any_backend not in values:
        values.append(any_backend)
    return values


OPEN_CAMERA_BUDGET_SECONDS = 10.0
START_TIMEOUT_SECONDS = 25.0  # models and camera together; a blocked driver call ends here
REJECTED_FRAMES = 3  # "stranger" frames that make an unfinished unlock try count as failed


def _open_camera(cv2: Any, start_index: int = 0, *, stop: Callable[[], bool] | None = None,
                 clock: Callable[[], float] = time.monotonic) -> tuple[Any, int]:
    """Find a working webcam. Each failed open can take seconds on some drivers, so the
    search checks ``stop`` between attempts and gives up after a short time budget."""
    last_error: Exception | None = None
    deadline = clock() + OPEN_CAMERA_BUDGET_SECONDS
    for offset in range(4):
        index = (start_index + offset) % 4
        for backend in _camera_backends(cv2):
            if stop is not None and stop():
                raise FaceCancelled("")  # the caller words it for its own mode
            if offset and clock() > deadline:
                raise FaceUnavailable(t("faceCapture.noUsableWebcamWasFound")) from last_error
            capture = None
            try:
                capture = cv2.VideoCapture(index, backend)
                if not capture or not capture.isOpened():
                    if capture:
                        capture.release()
                    continue
                capture.set(getattr(cv2, "CAP_PROP_FRAME_WIDTH", 3), 640)
                capture.set(getattr(cv2, "CAP_PROP_FRAME_HEIGHT", 4), 480)
                ok, frame = capture.read()
                if ok and frame is not None:
                    return capture, index
                capture.release()
            except Exception as exc:
                last_error = exc
                if capture is not None:
                    try:
                        capture.release()
                    except Exception:
                        # Best-effort optional step: it must never break the caller, so any error is ignored.
                        pass
    raise FaceUnavailable(
        t("faceCapture.noUsableWebcamWasFound")
    ) from last_error


def jpeg_preview(engine: Any) -> Callable[[Any, FaceObservation, float, str], str | None]:
    """A square, face-centred JPEG data URL of one frame, kept only in memory."""

    def encode(frame: Any, observation: FaceObservation, _progress: float, _state: str) -> str | None:
        cv2 = engine.cv2
        height, width = frame.shape[:2]
        side = min(width, height)
        if observation.bbox:
            x, y, w, h = observation.bbox
            cx, cy = x + w // 2, y + h // 2
        else:
            cx, cy = width // 2, height // 2
        left = max(0, min(width - side, cx - side // 2))
        top = max(0, min(height - side, cy - side // 2))
        square = cv2.resize(frame[top:top + side, left:left + side], (PREVIEW_PIXELS, PREVIEW_PIXELS))
        ok, data = cv2.imencode(".jpg", square, [int(getattr(cv2, "IMWRITE_JPEG_QUALITY", 1)), 70])
        if not ok:
            return None
        return "data:image/jpeg;base64," + base64.b64encode(data.tobytes()).decode("ascii")

    return encode


class FaceCapture:
    def __init__(self, mode: str, *, templates: Sequence[Sequence[float]] = (),
                 threshold: float = DEFAULT_MATCH_THRESHOLD, engine_factory: Callable[[], Any],
                 emit: Callable[[str, dict[str, Any]], None],
                 open_camera: Callable[[Any, int], tuple[Any, int]] = _open_camera,
                 clock: Callable[[], float] = time.monotonic,
                 encode: Callable[..., str | None] | None = None,
                 sleep: Callable[[float], None] = time.sleep,
                 challenge_factory: Callable[[], ActiveChallenge] = ActiveChallenge) -> None:
        if mode not in {"enroll", "verify"}:
            raise ValueError(t("faceCapture.unknownCameraOperation"))
        self.mode = mode
        self._cancelled = threading.Event()
        self._switch = threading.Event()
        self._templates = [list(values) for values in templates]
        self._threshold = float(threshold)
        self._engine_factory = engine_factory
        self._emit = emit
        if open_camera is _open_camera:
            # Let Cancel interrupt a slow camera search instead of waiting it out.
            open_camera = functools.partial(_open_camera, stop=self._cancelled.is_set)
        self._open_camera = open_camera
        self._clock = clock
        self._encode = encode
        self._sleep = sleep
        self._status: tuple[str, str] | None = None
        self._challenge_factory = challenge_factory
        self.challenge: ActiveChallenge | None = None  # unlock only, created by run()

    # ----------------------------------------------------------- control
    def cancel(self) -> None:
        self._cancelled.set()

    def switch_camera(self) -> None:
        self._switch.set()

    # ----------------------------------------------------------- helpers
    def _say(self, status: str, detail: str, progress: float, state: str = "running") -> None:
        if (status, detail) != self._status or state != "running":
            self._status = (status, detail)
            self._emit("face.status", {"status": status, "detail": detail, "progress": round(progress, 3),
                                       "state": state, "mode": self.mode})

    @staticmethod
    def _wipe(collection: list[list[float]]) -> None:
        for template in collection:
            for index in range(len(template)):
                template[index] = 0.0
        collection.clear()

    def _start(self) -> tuple[Any, Any, int]:
        """Load the face models and open the camera on a helper thread.

        A driver can block inside one open or first read for many seconds, where no
        check between attempts helps. Waiting here instead lets Cancel and the time
        limit end the run at once; a camera that opens after that is released again."""
        lock = threading.Lock()
        finished = threading.Event()
        box: dict[str, Any] = {"abandoned": False}

        def work() -> None:
            try:
                engine = self._engine_factory()
                opened, index = self._open_camera(engine.cv2, 0)
                box["value"] = (engine, opened, index)
            except BaseException as exc:  # noqa: BLE001 - handed to the waiting run
                box["error"] = exc
            with lock:
                finished.set()
                late = box.get("value") if box["abandoned"] else None
            if late is not None:
                try:
                    late[1].release()
                except Exception:  # noqa: BLE001, S110
                    pass

        threading.Thread(target=work, name="lgk-camera-start", daemon=True).start()
        deadline = time.monotonic() + START_TIMEOUT_SECONDS
        while not finished.wait(0.05):
            cancelled = self._cancelled.is_set()
            if cancelled or time.monotonic() > deadline:
                with lock:
                    if finished.is_set():
                        break  # it finished just now: use or release the result below
                    box["abandoned"] = True
                if cancelled:
                    raise FaceCancelled("")
                raise FaceUnavailable(t("faceCapture.noUsableWebcamWasFound"))
        if "error" in box:
            raise box["error"]
        return box["value"]

    # --------------------------------------------------------------- run
    def run(self) -> Any:
        capture = None
        strangers = 0
        samples: list[list[float]] = []
        try:
            try:
                self._say(t("cameraView.starting"), t(PRIVACY), 0.0)
                engine, capture, index = self._start()
                encode = self._encode or jpeg_preview(engine)
            except FaceModelError as exc:
                raise FaceUnavailable(str(exc)) from None
            liveness = PassiveLiveness()
            if self.mode == "verify":
                self.challenge = self._challenge_factory()
            run = 0
            counter = 0
            progress = 0.0
            started = last_frame = self._clock()
            last_preview = -FRAME_INTERVAL
            self._say(t("faceCapture.lookAtTheCamera"), t(PRIVACY), 0.0)
            while not self._cancelled.is_set():
                now = self._clock()
                if self._switch.is_set():
                    self._switch.clear()
                    self._wipe(samples)
                    run = 0
                    liveness, progress = PassiveLiveness(), 0.0
                    if self.challenge is not None:
                        self.challenge.restart()
                    self._say(t("qrImport.switchingCamera"), t(PRIVACY), 0.0)
                    # Keep the working camera until another one opens: with a single
                    # webcam the search finds nothing and the check carries on with it.
                    try:
                        replacement, index = self._open_camera(engine.cv2, (index + 1) % 4)
                    except FaceUnavailable:
                        replacement = None
                    if replacement is not None and replacement is not capture:
                        capture.release()
                        capture = replacement
                    self._say(t("faceCapture.lookAtTheCamera"), t(PRIVACY), 0.0)
                    last_frame = self._clock()  # the time limit keeps running across a switch
                    continue
                if now - started > TIMEOUT_SECONDS:
                    raise FaceError(t(TIMEOUT_TEXT))
                if self.challenge is not None and self.challenge.exhausted:
                    raise FaceError(t(CHALLENGE_FAILED))
                ok, frame = capture.read()
                if not ok or frame is None:
                    if self._clock() - last_frame > STALL_SECONDS:
                        raise FaceUnavailable(t(STALLED_TEXT))
                    self._sleep(0.08)
                    continue
                last_frame = self._clock()
                frame = engine.cv2.flip(frame, 1)
                observation = engine.analyze(frame)
                counter += 1
                liveness.update(observation)
                done: Any = None
                if not observation.usable:
                    if self.challenge is not None:
                        self.challenge.update(None, now)
                    self._say(observation.quality_reason or t("faceCapture.lookAtTheCamera"), t(PRIVACY), progress)
                elif self.mode == "enroll":
                    if liveness.completed and counter % 3 == 0:
                        feature = list(observation.feature or ())
                        if feature and abs(observation.yaw) <= 0.30:
                            if samples and not same_person(feature, samples):
                                self._say(t("faceCapture.lookAtTheCamera"), t("faceCapture.keepTheSameFaceIn"), progress)
                            else:
                                samples.append(feature)
                                progress = len(samples) / ENROLL_SAMPLES
                                self._say(t("faceCapture.keepMovingYourHeadSlowly"), t(PRIVACY), progress)
                                if len(samples) >= ENROLL_SAMPLES:
                                    done = [list(values) for values in samples]
                else:
                    challenge = self.challenge
                    if challenge is None:  # verify always has one; never unlock without it
                        raise FaceUnavailable(t(CRASHED_TEXT))
                    verdict = frame_verdict(observation.feature or (), self._templates, self._threshold)
                    if verdict == "stranger":
                        run = 0
                        strangers += 1
                        # Someone else is in view: the check starts over, liveness and the
                        # movement challenge included, so two people's frames never add up.
                        liveness = PassiveLiveness()
                        challenge.restart()
                        self._say(t("faceCapture.faceNotRecognised"), t("faceCapture.tryBetterLightingOrUse"), 0.0)
                    else:
                        run = run + 1 if verdict == "match" else 0
                        was_done = challenge.completed
                        challenge.update(observation.landmarks, now, matched=verdict == "match")
                        if challenge.completed and not was_done:
                            run = 0  # the owner must be seen again after the last movement
                        status = t(challenge.prompt) if challenge.prompt else t("faceCapture.lookAtTheCamera")
                        self._say(status, t(CHALLENGE_RETRY) if challenge.missed else t(PRIVACY), progress)
                    progress = min(liveness.progress, 0.8 * challenge.progress
                                   + (0.2 * min(1.0, run / VERIFY_RUN) if challenge.completed else 0.0))
                    if liveness.completed and challenge.completed and run >= VERIFY_RUN:
                        done = True
                if done is not None:
                    self._say(t("faceCapture.faceRecognised") if self.mode == "verify" else t("faceCapture.faceSetUp"), "", 1.0, "success")
                    return done
                if now - last_preview >= FRAME_INTERVAL and not self._cancelled.is_set():
                    last_preview = now
                    try:
                        image = encode(frame, observation, progress, "running")
                    except Exception:  # noqa: BLE001 - a preview failure never unlocks anything
                        image = None
                    if image:
                        self._emit("face.frame", {"image": image, "progress": round(progress, 3)})
                self._sleep(0.04)
            raise FaceCancelled(t(CANCELLED_TEXT) if self.mode == "verify" else t("faceCapture.cameraEnrollmentWasCancelled"))
        except (FaceError, FaceCancelled) as exc:
            if isinstance(exc, FaceCancelled) and not str(exc):
                exc = FaceCancelled(t(CANCELLED_TEXT) if self.mode == "verify"
                                    else t("faceCapture.cameraEnrollmentWasCancelled"))
            # A run that clearly saw someone else counts as a failed try even when it
            # is cancelled or the camera stalls, so cancelling cannot dodge the back-off.
            # So does a run where the owner's face ignored or missed the asked movement.
            exc.face_rejected = (strangers >= REJECTED_FRAMES
                                 or (self.challenge is not None and self.challenge.failures > 0))
            self._say(str(exc), "", 0.0, "cancelled" if isinstance(exc, FaceCancelled) else "failed")
            raise exc from None
        except Exception:
            self._say(t(CRASHED_TEXT), "", 0.0, "failed")
            raise FaceUnavailable(t(CRASHED_TEXT)) from None
        finally:
            if capture is not None:
                try:
                    capture.release()
                except Exception:  # noqa: BLE001, S110
                    pass
            self._wipe(samples)
            self._wipe(self._templates)
