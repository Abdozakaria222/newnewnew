"""Entry point.
  python -m netoptimizer            full dashboard in a native window (no browser)
  python -m netoptimizer --simple   small Tkinter window (one screen, plain-language verdicts)
  python -m netoptimizer --web      the dashboard in your normal browser"""
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
    ap.add_argument("--web", action="store_true", help="open the dashboard in the normal browser")
    ap.add_argument("--simple", action="store_true", help="small one-screen Tkinter window")
    ap.add_argument("--port", type=int, default=None)
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args(argv)
    if sys.version_info < (3, 9):
        print("Python 3.9 or newer is required.")
        return 1
    from .app import App
    app = App()
    if not args.web and not args.simple:
        from .gui import webwindow
        if webwindow.run(app):
            return 0
        print("Embedded window unavailable (pywebview / WebView2 missing) - using the simple window.")
        args.simple = True
    if args.simple:
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
