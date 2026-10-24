"""Local RGB-webcam face detection and recognition primitives.

The camera path is deliberately optional and imported lazily.  The native host
never imports OpenCV and the master-password route never opens a camera.

The bundled/downloaded models are the OpenCV Zoo YuNet detector and SFace
recognizer.  Model bytes are hash-pinned before they are loaded.
"""
from __future__ import annotations

import hashlib
import math
import os
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

YUNET_NAME = "face_detection_yunet_2023mar.onnx"
YUNET_SHA256 = "8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4"
SFACE_NAME = "face_recognition_sface_2021dec_int8bq.onnx"
SFACE_SHA256 = "fb143eea07838aa532d1c95df5f69899974ea0140e1fba05e94204be13ed74ee"
MODEL_ID = f"opencv-sface-2021dec-int8bq-{SFACE_SHA256[:16]}"
EMBEDDING_SIZE = 128
DEFAULT_MATCH_THRESHOLD = 0.45


class FaceModelError(RuntimeError):
    """A safe, non-biometric diagnostic suitable for the local UI."""


@dataclass(frozen=True)
class FaceObservation:
    """One frame's non-image face measurements and normalized embedding."""

    face_count: int
    bbox: tuple[int, int, int, int] | None = None
    score: float = 0.0
    brightness: float = 0.0
    yaw: float = 0.0
    scale: float = 0.0
    centered: bool = False
    feature: tuple[float, ...] | None = None
    quality_reason: str = ""

    @property
    def usable(self) -> bool:
        return self.face_count == 1 and self.feature is not None and not self.quality_reason


def model_directory() -> Path:
    override = os.environ.get("LOCALGATEKEYS_FACE_MODEL_DIR")
    return Path(override).expanduser().resolve() if override else Path(__file__).resolve().parent / "models"


def model_paths() -> tuple[Path, Path]:
    root = model_directory()
    return root / YUNET_NAME, root / SFACE_NAME


@lru_cache(maxsize=8)
def _verify_file(path_text: str, expected: str, size: int, mtime_ns: int) -> None:
    path = Path(path_text)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != expected:
        raise FaceModelError(
            f"Camera verification model {path.name} failed its integrity check. "
            "Rebuild LocalGateKeys from a clean project copy."
        )


def require_model_files() -> tuple[Path, Path]:
    paths = model_paths()
    for path, expected in zip(paths, (YUNET_SHA256, SFACE_SHA256), strict=True):
        try:
            stat = path.stat()
        except OSError as exc:
            raise FaceModelError(
                "Camera verification models are missing. Run scripts\\fetch_face_models.ps1 "
                "and rebuild the installer. Master-password unlocking is unaffected."
            ) from exc
        if not path.is_file() or stat.st_size < 1024:
            raise FaceModelError(f"Camera verification model {path.name} is incomplete.")
        _verify_file(str(path), expected, stat.st_size, stat.st_mtime_ns)
    return paths


def normalize_embedding(values: Sequence[float]) -> tuple[float, ...]:
    if len(values) != EMBEDDING_SIZE:
        raise FaceModelError("The face-recognition model returned an unexpected template size.")
    cleaned = tuple(float(value) for value in values)
    if any(not math.isfinite(value) for value in cleaned):
        raise FaceModelError("The face-recognition model returned invalid template data.")
    norm = math.sqrt(sum(value * value for value in cleaned))
    if norm <= 1e-9:
        raise FaceModelError("The face-recognition model returned an empty template.")
    return tuple(value / norm for value in cleaned)


def cosine_score(first: Sequence[float], second: Sequence[float]) -> float:
    if len(first) != EMBEDDING_SIZE or len(second) != EMBEDDING_SIZE:
        return -1.0
    return float(sum(float(a) * float(b) for a, b in zip(first, second, strict=True)))


def best_match(feature: Sequence[float], templates: Iterable[Sequence[float]]) -> float:
    return max((cosine_score(feature, template) for template in templates), default=-1.0)


class FaceEngine:
    """YuNet + SFace inference.  No image is retained by this object."""

    def __init__(self) -> None:
        detector_path, recognizer_path = require_model_files()
        try:
            import cv2  # type: ignore
            import numpy as np  # type: ignore
        except Exception as exc:
            raise FaceModelError(
                "OpenCV camera support is unavailable. Reinstall/rebuild LocalGateKeys; "
                "your master password still works."
            ) from exc
        self.cv2, self.np = cv2, np
        try:
            detector_factory = getattr(cv2, "FaceDetectorYN_create", None)
            if detector_factory is None:
                detector_factory = cv2.FaceDetectorYN.create
            recognizer_factory = getattr(cv2, "FaceRecognizerSF_create", None)
            if recognizer_factory is None:
                recognizer_factory = cv2.FaceRecognizerSF.create
            self.detector = detector_factory(str(detector_path), "", (320, 320), 0.90, 0.30, 5000)
            self.recognizer = recognizer_factory(str(recognizer_path), "")
        except Exception as exc:
            raise FaceModelError(
                "The installed OpenCV build could not load the camera verification models. "
                "Rebuild with the pinned OpenCV dependency."
            ) from exc

    def analyze(self, frame: Any) -> FaceObservation:
        cv2, np = self.cv2, self.np
        if frame is None or not hasattr(frame, "shape") or len(frame.shape) < 2:
            return FaceObservation(0, quality_reason="Camera did not return an image.")
        height, width = int(frame.shape[0]), int(frame.shape[1])
        if width < 240 or height < 180:
            return FaceObservation(0, quality_reason="Camera image is too small.")
        try:
            self.detector.setInputSize((width, height))
            _ok, faces = self.detector.detect(frame)
        except Exception as exc:
            raise FaceModelError("Face detection failed for this camera frame.") from exc
        if faces is None or len(faces) == 0:
            return FaceObservation(0, quality_reason="Place one face inside the frame.")
        if len(faces) != 1:
            return FaceObservation(int(len(faces)), quality_reason="Only one person may be visible.")

        face = np.asarray(faces[0], dtype=np.float32)
        x, y, box_w, box_h = (float(face[i]) for i in range(4))
        score = float(face[14]) if len(face) > 14 else 0.0
        left = max(0, int(round(x)))
        top = max(0, int(round(y)))
        right = min(width, int(round(x + box_w)))
        bottom = min(height, int(round(y + box_h)))
        box_w_i, box_h_i = max(0, right - left), max(0, bottom - top)
        bbox = (left, top, box_w_i, box_h_i)
        scale = math.sqrt(max(0.0, box_w * box_h) / float(width * height))
        center_x, center_y = x + box_w / 2.0, y + box_h / 2.0
        centered = abs(center_x - width / 2.0) <= width * 0.28 and abs(center_y - height / 2.0) <= height * 0.30

        # YuNet outputs five landmarks after the bounding box: two eyes, nose,
        # and two mouth corners.  Sort eye x positions so camera mirroring does
        # not change the normalized yaw calculation.
        eye1_x, eye1_y, eye2_x, eye2_y = (float(face[i]) for i in range(4, 8))
        nose_x = float(face[8])
        eye_distance = math.hypot(eye2_x - eye1_x, eye2_y - eye1_y)
        yaw = 0.0 if eye_distance < 1.0 else (nose_x - (eye1_x + eye2_x) / 2.0) / eye_distance

        reason = ""
        minimum = max(105, int(min(width, height) * 0.22))
        if score < 0.90:
            reason = "Move into clearer view."
        elif box_w_i < minimum or box_h_i < minimum:
            reason = "Move a little closer to the camera."
        elif left <= 2 or top <= 2 or right >= width - 2 or bottom >= height - 2:
            reason = "Keep your whole face inside the frame."
        elif not centered:
            reason = "Center your face in the frame."

        brightness = 0.0
        if box_w_i and box_h_i:
            region = frame[top:bottom, left:right]
            try:
                brightness = float(cv2.cvtColor(region, cv2.COLOR_BGR2GRAY).mean())
            except Exception:
                brightness = 0.0
        if not reason and brightness < 42:
            reason = "Increase the light on your face."
        elif not reason and brightness > 225:
            reason = "Reduce strong light or glare."

        feature: tuple[float, ...] | None = None
        if not reason:
            try:
                aligned = self.recognizer.alignCrop(frame, face)
                raw = self.recognizer.feature(aligned)
                feature = normalize_embedding(np.asarray(raw, dtype=np.float32).reshape(-1).tolist())
            except FaceModelError:
                raise
            except Exception as exc:
                raise FaceModelError("Face alignment or recognition failed for this frame.") from exc
        return FaceObservation(1, bbox, score, brightness, yaw, scale, centered, feature, reason)
