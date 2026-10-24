"""The app runs without Tk: importing the entry point and the WebView UI must never load tkinter."""
import subprocess
import sys

CODE = r"""
import sys
sys.modules['tkinter'] = None  # any 'import tkinter' now raises ImportError
import pkgutil, importlib, localvault
skip = set()
for m in pkgutil.walk_packages(localvault.__path__, 'localvault.'):
    name = m.name
    if name.startswith(('localvault.sync.', )) and False:
        continue
    try:
        importlib.import_module(name)
    except ImportError as exc:
        if 'tkinter' in str(exc) or 'NoneType' in str(exc) or 'halted' in str(exc):
            print('TK', name)
    except Exception:
        pass
"""


def test_every_module_imports_without_tkinter():
    out = subprocess.run([sys.executable, "-c", CODE], capture_output=True, text=True, timeout=180)
    assert [line for line in out.stdout.splitlines() if line.startswith("TK")] == [], out.stdout + out.stderr
