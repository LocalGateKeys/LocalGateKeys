"""Camera enrolment and verification without Tk, for the WebView UI.

The per-frame logic of ``face_ui._CameraDialog`` (passive liveness, 8 enrolment
samples, 4 matching frames out of the last 7) runs on a worker thread. The page
gets ``face.status`` updates and throttled ``face.frame`` previews: small JPEG
data URLs that exist only in memory and are never written to disk.
"""
from __future__ import annotations

import base64
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


def _open_camera(cv2: Any, start_index: int = 0) -> tuple[Any, int]:
    last_error: Exception | None = None
    for offset in range(4):
        index = (start_index + offset) % 4
        for backend in _camera_backends(cv2):
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
                 sleep: Callable[[float], None] = time.sleep) -> None:
        if mode not in {"enroll", "verify"}:
            raise ValueError(t("faceCapture.unknownCameraOperation"))
        self.mode = mode
        self._templates = [list(values) for values in templates]
        self._threshold = float(threshold)
        self._engine_factory = engine_factory
        self._emit = emit
        self._open_camera = open_camera
        self._clock = clock
        self._encode = encode
        self._sleep = sleep
        self._cancelled = threading.Event()
        self._switch = threading.Event()
        self._status: tuple[str, str] | None = None

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

    # --------------------------------------------------------------- run
    def run(self) -> Any:
        capture = None
        samples: list[list[float]] = []
        try:
            try:
                engine = self._engine_factory()
                encode = self._encode or jpeg_preview(engine)
                self._say(t("cameraView.starting"), t(PRIVACY), 0.0)
                capture, index = self._open_camera(engine.cv2, 0)
            except FaceModelError as exc:
                raise FaceUnavailable(str(exc)) from None
            liveness = PassiveLiveness()
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
                    capture.release()
                    capture = None
                    self._wipe(samples)
                    run = 0
                    liveness, progress = PassiveLiveness(), 0.0
                    self._say(t("qrImport.switchingCamera"), t(PRIVACY), 0.0)
                    capture, index = self._open_camera(engine.cv2, (index + 1) % 4)
                    started = last_frame = self._clock()
                    continue
                if now - started > TIMEOUT_SECONDS:
                    raise FaceError(t(TIMEOUT_TEXT))
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
                    verdict = frame_verdict(observation.feature or (), self._templates, self._threshold)
                    if verdict == "match":
                        run += 1
                        self._say(t("faceCapture.lookAtTheCamera"), t(PRIVACY), progress)
                    else:
                        run = 0
                        if verdict == "stranger":
                            # Someone else is in view: the check starts over, liveness included,
                            # so frames from two people can never add up to an unlock.
                            liveness = PassiveLiveness()
                            self._say(t("faceCapture.faceNotRecognised"), t("faceCapture.tryBetterLightingOrUse"), 0.0)
                    progress = min(liveness.progress, run / VERIFY_RUN)
                    if liveness.completed and run >= VERIFY_RUN:
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
            self._say(str(exc), "", 0.0, "cancelled" if isinstance(exc, FaceCancelled) else "failed")
            raise
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
