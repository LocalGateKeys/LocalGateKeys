from __future__ import annotations

from localvault.face_models import EMBEDDING_SIZE, FaceObservation, best_match, normalize_embedding
from localvault.app.face_capture import PassiveLiveness


def observation(yaw=0.0, scale=0.30, x=100):
    feature = normalize_embedding([1.0] + [0.0] * (EMBEDDING_SIZE - 1))
    return FaceObservation(
        face_count=1, bbox=(x, 80, 180, 180), score=0.99, brightness=120.0,
        yaw=yaw, scale=scale, centered=True, feature=feature,
    )


def test_static_face_never_passes_liveness():
    liveness = PassiveLiveness()
    for _ in range(30):
        liveness.update(observation())
    assert not liveness.completed


def test_natural_micro_motion_passes_without_prompted_steps():
    liveness = PassiveLiveness()
    for index in range(liveness.frames_needed):
        liveness.update(observation(yaw=0.01 * (index % 2), x=100 + index % 3))
    assert liveness.completed
    assert liveness.progress == 1.0


def test_large_jump_restarts_liveness():
    liveness = PassiveLiveness()
    for index in range(liveness.frames_needed - 1):
        liveness.update(observation(x=100 + index))
    liveness.update(observation(x=400))
    assert not liveness.completed
    assert len(liveness.samples) == 1


def test_unusable_frame_resets_progress():
    liveness = PassiveLiveness()
    for index in range(3):
        liveness.update(observation(x=100 + index))
    liveness.update(FaceObservation(0, quality_reason="Place one face inside the frame."))
    assert liveness.progress == 0.0





def test_embedding_math_is_normalized_and_rejects_unrelated_template():
    one = normalize_embedding([1.0] + [0.0] * (EMBEDDING_SIZE - 1))
    nearby = normalize_embedding([1.0, 0.1] + [0.0] * (EMBEDDING_SIZE - 2))
    other = normalize_embedding([0.0, 1.0] + [0.0] * (EMBEDDING_SIZE - 2))
    assert best_match(nearby, [one]) > 0.9
    assert best_match(other, [one]) < 0.1
