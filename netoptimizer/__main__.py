"""Entry point.  python -m netoptimizer          -> desktop window (no browser)
                 python -m netoptimizer --web     -> old browser dashboard"""
from __future__ import annotations

import argparse
import os
import sys


def _fix_windowed_streams():
    # PyInstaller --windowed has no console: stdout/stderr are None.
    for name in ("stdout", "stderr"):
        if getattr(sys, name) is None:
            setattr(sys, name, open(os.devnull, "w"))


def main(argv=None) -> int:
    _fix_windowed_streams()
    ap = argparse.ArgumentParser(prog="netoptimizer", description="NetworkOptimizer — أفضل DNS وMTU")
    ap.add_argument("--web", action="store_true", help="use the browser dashboard instead of the desktop window")
    ap.add_argument("--port", type=int, default=None)
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args(argv)
    if sys.version_info < (3, 9):
        print("Python 3.9 or newer is required.")
        return 1
    from .app import App
    app = App()
    if not args.web:
        from .gui.window import Window
        Window(app).run()
        return 0
    from .ui.server import serve
    httpd, _ = serve(app, args.port, not args.no_browser)
    try:
        httpd.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        app.monitor.stop()
        httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
