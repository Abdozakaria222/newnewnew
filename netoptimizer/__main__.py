"""Entry point:  python -m netoptimizer  [--no-browser] [--port N]"""
from __future__ import annotations

import argparse
import sys


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="netoptimizer", description="NetworkOptimizer — evidence-based DNS & MTU tuning")
    ap.add_argument("--port", type=int, default=None)
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args(argv)
    if sys.version_info < (3, 9):
        print("Python 3.9 or newer is required.")
        return 1
    from .app import App
    from .ui.server import serve
    app = App()
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
