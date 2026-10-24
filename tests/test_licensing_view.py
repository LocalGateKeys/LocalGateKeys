import datetime as dt

from localvault.licensing import License, LicenseStatus
from localvault.app.licence_view import PURCHASE_URL, licence_view
from localvault.shell.nav import TOOLS_ENTRIES
from localvault.app.presentation import licence_warning_text

LIC = License("LGK-1", "pro", "Ada Lovelace", "ada@example.com",
              dt.date(2026, 1, 1), dt.date(2027, 1, 1))


def _st(state, lic=None, message=""):
    return LicenseStatus(state, lic, message)


def test_pro_view():
    v = licence_view(_st("pro", LIC))
    assert "Pro" in v.headline
    text = " ".join(v.detail_lines)
    assert "Ada Lovelace" in text and "2027-01-01" in text
    assert v.can_remove and not v.warning


def test_holder_named_once_when_name_is_email():
    lic = License("LGK-2", "pro", "ada@example.com", "ada@example.com",
                  dt.date(2026, 1, 1), dt.date(2027, 1, 1))
    assert licence_view(_st("pro", lic)).detail_lines[0] == "Licensed to: ada@example.com"
    assert licence_view(_st("pro", LIC)).detail_lines[0] == "Licensed to: Ada Lovelace (ada@example.com)"


def test_free_view():
    v = licence_view(_st("free"))
    assert "Free" in v.headline
    assert not v.can_remove and not v.warning
    text = " ".join(v.detail_lines)
    # Sync, two-factor codes and attachments are Pro-only; desktop fill stays free.
    assert "sync" in text.lower() and "two-factor" in text.lower() and "desktop" not in text.lower()
    assert "4 items" in text


def test_free_view_shows_item_usage():
    v = licence_view(_st("free"), item_count=3)
    assert v.detail_lines[0] == "Free plan: 3 of 4 items used"
    over = licence_view(_st("free"), item_count=6)
    assert over.detail_lines[0] == "Free plan: 6 of 4 items used"


def test_licence_problem_views_show_item_usage():
    for state in ("expired_for_this_build", "revoked", "invalid"):
        v = licence_view(_st(state, LIC, "Problem."), item_count=2)
        assert "Free plan: 2 of 4 items used" in v.detail_lines


def test_pro_and_unconfigured_views_have_no_usage_line():
    for st in (_st("pro", LIC), _st("unconfigured")):
        v = licence_view(st, item_count=9)
        assert not any("items used" in line for line in v.detail_lines)


def test_unconfigured_view():
    v = licence_view(_st("unconfigured"))
    assert v.headline == "Pro features are enabled in this build"
    assert "development" not in (v.headline + " ".join(v.detail_lines)).lower()
    assert not v.can_remove and not v.warning


def test_expired_view_warns_and_can_remove():
    v = licence_view(_st("expired_for_this_build", LIC))
    assert v.warning and v.can_remove
    assert "2027-01-01" in " ".join(v.detail_lines)


def test_revoked_and_invalid_warn():
    r = licence_view(_st("revoked", LIC, "Revoked."))
    i = licence_view(_st("invalid", None, "Bad file."))
    assert r.warning and r.can_remove
    assert i.warning and i.can_remove
    assert "Bad file." in " ".join(i.detail_lines)


def test_purchase_url_is_the_site_checkout():
    assert PURCHASE_URL == "https://localgatekeys.app/buy"


def test_nav_has_licence_entry_after_devices():
    labels = [e.label for e in TOOLS_ENTRIES]
    assert labels.index("Licence") == labels.index("Devices & connections") + 1
    entry = TOOLS_ENTRIES[labels.index("Licence")]
    assert entry.action == "licence_clicked" and entry.icon == "nav.settings"


def test_statusbar_warning_text():
    assert licence_warning_text(_st("pro", LIC)) == ""
    assert licence_warning_text(_st("free")) == ""
    assert licence_warning_text(_st("unconfigured")) == ""
    for state in ("expired_for_this_build", "revoked", "invalid"):
        assert licence_warning_text(_st(state, LIC))


def test_upgrade_prompt_free_shows_item_limit_pitch():
    from localvault.app.licence_view import upgrade_prompt_text
    head, body = upgrade_prompt_text(_st("free"))
    assert head == "The free plan holds up to 4 items."
    assert body == ("LocalGateKeys Pro: unlimited items, device sync, two-factor codes and attachments — "
                    "US$4.99 once, lifetime updates.")


def test_upgrade_prompt_names_sync_but_never_desktop_fill():
    from localvault.app.licence_view import upgrade_prompt_text
    for state in ("free", "expired_for_this_build", "revoked", "invalid"):
        head, body = upgrade_prompt_text(_st(state, LIC, "Msg."))
        text = (head + body).lower()
        assert "sync" in text and "desktop" not in text


def test_upgrade_prompt_shows_licence_problem_instead_of_pitch():
    from localvault.app.licence_view import upgrade_prompt_text
    for state, msg in (("expired_for_this_build", "Covers until 2027-01-01."),
                       ("revoked", "This licence has been revoked."),
                       ("invalid", "The installed licence is not usable.")):
        head, body = upgrade_prompt_text(_st(state, LIC, msg))
        assert head == msg
        assert "US$" not in body
        assert "vault" in body and "4 items" in body


def test_no_feature_specific_pro_texts_remain():
    import localvault.app.licence_view as ui
    assert not hasattr(ui, "_FEATURE_TEXT")


def test_install_result_text_reflects_status():
    from localvault.app.licence_view import install_result_text
    assert install_result_text(_st("pro", LIC), LIC) == f"Licence installed for {LIC.name}."
    text = install_result_text(_st("expired_for_this_build", LIC, "Covers until 2027-01-01."), LIC)
    assert "not active" in text and "Covers until 2027-01-01." in text
    assert install_result_text(_st("revoked", LIC, "This licence has been revoked."), LIC).endswith(
        "This licence has been revoked.")


