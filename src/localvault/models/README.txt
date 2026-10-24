LocalGateKeys ordinary-webcam verification uses two OpenCV Zoo models:

- YuNet face detector: face_detection_yunet_2023mar.onnx (MIT license)
- SFace face recognizer: face_recognition_sface_2021dec_int8bq.onnx (Apache-2.0 license)

The model files are fetched at build time by scripts/fetch_face_models.ps1 from
OpenCV's official model hosting and accepted only when their pinned SHA-256
hashes match src/localvault/face_models.py. Runtime verification is local and
does not download models or send camera frames anywhere.
