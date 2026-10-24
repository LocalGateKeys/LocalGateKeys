"""Personal installer entry; self-check opens no vault, camera, or auth prompt."""
import sys

if __name__ == "__main__":
    if sys.argv[1:] == ["--check-build", "--release"]:
        from localvault.build_check import main
        raise SystemExit(main(require_camera=True, require_license_keys=True))
    if sys.argv[1:] == ["--check-build"]:
        from localvault.build_check import main
        raise SystemExit(main(require_camera=True))
    from localvault.agent import main
    main()
