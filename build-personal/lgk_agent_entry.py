"""Personal installer entry; self-check opens no vault, camera, or auth prompt."""
import sys


def _harden():
    """DLL search order and image-load policy, before any DLL-heavy import."""
    from localvault.process_hardening import check_hardened, harden_process

    result = harden_process()
    if sys.argv[1:2] == ["--check-build"]:
        problem = check_hardened(result)
        if problem:
            stream = sys.stderr or sys.stdout
            if stream is not None:
                print(f"LocalGateKeys build check failed: {problem}", file=stream)
            raise SystemExit(1)
    elif not result.ok:
        import logging

        logging.getLogger("localvault.process_hardening").warning("process hardening incomplete: %s", result.describe())


if __name__ == "__main__":
    _harden()
    if sys.argv[1:] == ["--check-build", "--release"]:
        from localvault.build_check import main
        raise SystemExit(main(require_camera=True, require_license_keys=True))
    if sys.argv[1:] == ["--check-build"]:
        from localvault.build_check import main
        raise SystemExit(main(require_camera=True))
    from localvault.agent import main
    main()
