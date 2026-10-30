// A QR picture from the file picker, a drop or a paste, read to a data URL in memory (never saved).
// Python checks the type and size again before decoding; this check only answers early.

export const PICTURE_TYPES = ['image/png', 'image/jpeg', 'image/bmp'];
export const MAX_PICTURE_BYTES = 12 * 1024 * 1024;

export function readPicture(file) {
  if (!PICTURE_TYPES.includes(file.type)) return Promise.resolve({ error: 'Use a PNG, JPEG or BMP picture of the QR code.' });
  if (file.size > MAX_PICTURE_BYTES) return Promise.resolve({ error: 'That picture is too large. Crop it to the QR code.' });
  return new Promise((resolve) => {
    const reader = new FileReader();
    reader.onload = () => resolve({ dataUrl: String(reader.result) });
    reader.onerror = () => resolve({ error: 'That picture could not be read.' });
    reader.readAsDataURL(file);
  });
}
