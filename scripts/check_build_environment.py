"""Run against this checkout, not an old installed LocalGateKeys package."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

if __name__ == "__main__":
    import importlib.util
    if importlib.util.find_spec("PyInstaller") is None:
        raise SystemExit('Missing PyInstaller. Run .\\.venv\\Scripts\\python.exe -m pip install -e ".[dev,build]"')
    from localvault.build_check import main
    raise SystemExit(main(require_camera=True))
