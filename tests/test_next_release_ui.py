from __future__ import annotations

import json
from pathlib import Path

import pytest

from localvault.next_release_ui import (
    EditorUndoModel,
    FormValidationError,
    GuidedRecoveryDrill,
    OnboardingController,
    OnboardingStore,
    RecoveryDrillStage,
    StaleEditorError,
    TemplateValidationError,
    dpi_metrics,
    preview_form,
    resolve_theme,
    validate_form_values,
    validate_template_definition,
)


def _template() -> dict:
    return {
        "id": "custom.note",
        "kind": "note",
        "name": "Custom note",
        "version": 2,
        "fields": [
            {"id": "title", "label": "Title", "type": "text", "required": True},
            {"id": "secret_value", "label": "Private value", "type": "secret"},
            {"id": "kind", "label": "Kind", "type": "choice", "choices": ["one", "two"]},
        ],
    }


def test_template_validation_and_masked_preview() -> None:
    schema = validate_template_definition(_template())
    values = validate_form_values(schema, {"title": "hello", "secret_value": "hidden", "kind": "one"})
    assert values["title"] == "hello"
    assert preview_form(schema, values)["secret_value"] == "••••••••"
    assert preview_form(schema, values, reveal_secrets=True)["secret_value"] == "hidden"


def test_template_rejects_executable_data_and_secret_defaults() -> None:
    with pytest.raises(TemplateValidationError):
        validate_template_definition({**_template(), "script": "return secret"})
    bad = _template()
    bad["fields"] = [{"id": "private", "type": "secret", "default": "do not persist"}]
    with pytest.raises(TemplateValidationError):
        validate_template_definition(bad)


def test_form_field_errors_are_field_level() -> None:
    schema = validate_template_definition(_template())
    with pytest.raises(FormValidationError) as exc:
        validate_form_values(schema, {"kind": "three"})
    assert "title" in exc.value.errors
    assert "kind" in exc.value.errors


def test_editor_history_is_bounded_and_clears_on_lock() -> None:
    editor = EditorUndoModel({"value": "first"}, max_entries=2)
    editor.set_value("value", "second")
    editor.set_value("value", "third")
    assert editor.dirty is True
    assert editor.undo()["value"] == "second"
    assert editor.redo()["value"] == "third"
    editor.clear_on_lock()
    with pytest.raises(StaleEditorError):
        _ = editor.values


def test_onboarding_progress_resumes_and_never_serializes_passwords(workspace_tmp: Path) -> None:
    store = OnboardingStore(workspace_tmp / "onboarding.json")
    flow = OnboardingController("profile-a", store)
    flow.choose("offline_mode", True)
    flow.advance("security")
    flow.skip("security")
    resumed = OnboardingController("profile-a", store)
    assert resumed.state.stage == "security"
    assert resumed.state.choices == {"offline_mode": True}
    raw = json.loads((workspace_tmp / "onboarding.json").read_text(encoding="utf-8"))
    assert "password" not in repr(raw).casefold()


def test_onboarding_lock_invalidates_mutation(workspace_tmp: Path) -> None:
    from localvault.session_guard import StaleSession

    flow = OnboardingController("profile-a", OnboardingStore(workspace_tmp / "state.json"))
    flow.invalidate()
    with pytest.raises(StaleSession):
        flow.choose("offline_mode", True)


def test_theme_and_dpi_tokens_cover_system_modes() -> None:
    assert resolve_theme("system", system_is_dark=False).mode.value == "light"
    assert resolve_theme("high_contrast").high_contrast is True
    assert dpi_metrics(dpi=192) == {"padding": 24, "row_height": 64, "font_size": 20}


class _FakeRecoveryService:
    def __init__(self) -> None:
        self.calls: list[tuple[str, object]] = []
        self.last_backup = None

    def create_backup(self, destination, **kwargs):
        self.calls.append(("create", destination))
        return {"operation": "create", "path": str(destination), "verified": True, "sha256": "a" * 64}

    def inspect_backup(self, source, **kwargs):
        self.calls.append(("inspect", source))
        return {"operation": "inspect", "path": str(source), "verified": False, "dry_run": True}

    def verify_backup(self, source, **kwargs):
        self.calls.append(("verify", source))
        return {"operation": "verify", "path": str(source), "verified": True, "dry_run": True, "sha256": "a" * 64}

    def plan_restore(self, source, destination, **kwargs):
        self.calls.append(("plan", destination))
        return {"operation": "restore", "source": str(source), "destination": str(destination), "dry_run": True, "requires_confirmation": True}

    def restore(self, source, destination, **kwargs):
        self.calls.append(("restore", destination))
        return {"operation": "restore", "source": str(source), "destination": str(destination), "committed": kwargs["confirm"]}

    def recovery_kit(self, destination, **kwargs):
        self.calls.append(("kit", destination))
        return {"operation": "recovery-kit", "path": str(destination), "committed": True}


def test_guided_recovery_routes_stages_and_does_not_retain_passwords(workspace_tmp: Path) -> None:
    service = _FakeRecoveryService()
    drill = GuidedRecoveryDrill(
        service=service,
        catalog_verifier=lambda path, password: {"catalog_verified": True, "reachable_blobs_verified": True},
    )
    backup = workspace_tmp / "backup.lgk"
    trial = workspace_tmp / "trial"
    drill.create(backup, backup_password="backup only")
    drill.inspect(backup, backup_password="backup only")
    drill.verify(backup, backup_password="backup only", vault_password="vault only")
    drill.plan(backup, trial, backup_password="backup only", vault_password="vault only")
    drill.test_restore(backup, trial, confirm=True, backup_password="backup only", vault_password="vault only")
    drill.verify_restored_catalog(trial, vault_password="vault only")
    drill.kit(workspace_tmp / "kit.json", backup=backup)
    assert drill.state.stage is RecoveryDrillStage.KIT_WRITTEN
    assert "password" not in repr(drill.state).casefold()
    assert [name for name, _ in service.calls] == ["create", "inspect", "verify", "plan", "restore", "kit"]


def test_guided_restore_rechecks_session_before_confirmed_mutation(workspace_tmp: Path) -> None:
    service = _FakeRecoveryService()
    drill = GuidedRecoveryDrill(service=service, session_checker=lambda: (_ for _ in ()).throw(RuntimeError("stale")))

    with pytest.raises(RuntimeError, match="stale"):
        drill.test_restore(workspace_tmp / "backup.lgk", workspace_tmp / "trial", confirm=True)

    assert not any(name == "restore" for name, _ in service.calls)
