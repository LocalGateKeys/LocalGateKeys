import ast
from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parents[1]


def test_multires_icon_assets_are_valid():
    icons = ROOT / 'assets' / 'icons'
    for size in (16, 20, 24, 32, 40, 48, 64, 96, 128, 256):
        path = icons / f'app_{size}.png'
        assert path.exists()
        with Image.open(path) as im:
            assert im.size == (size, size)
    assert (icons / 'localgatekeys.ico').exists()


def test_installer_shortcuts_are_current_user_only():
    text = (ROOT / 'scripts' / 'install_windows.ps1').read_text(encoding='utf-8')
    assert '[Environment]::GetFolderPath("Desktop")' in text
    assert '[Environment]::GetFolderPath("Programs")' in text
    assert 'localgatekeys.ico' in text
    assert 'HKLM' not in text.replace('Nothing is written to Program Files or HKLM', '')


def test_changed_python_parses():
    for rel in (
        'src/localvault/agent.py',
        'src/localvault/settings_ui.py',
        'src/localvault/tray.py',
    ):
        ast.parse((ROOT / rel).read_text(encoding='utf-8'))
