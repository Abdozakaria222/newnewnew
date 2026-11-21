"""The full dashboard (same pages and details as the browser version) inside a
native desktop window, using the system WebView (Edge WebView2 on Windows 10/11).
No browser tab is opened. Needs the optional `pywebview` package (bundled in the EXE)."""
from __future__ import annotations

import threading

from ..core import settings


def run(app) -> bool:
    """Returns False if the embedded window cannot be used (caller falls back)."""
    try:
        import webview
    except Exception:
        return False
    from ..ui.server import serve
    httpd, url = serve(app, None, False)
    threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.5}, daemon=True).start()
    try:
        try:
            webview.settings["ALLOW_DOWNLOADS"] = True
        except Exception:
            pass
        webview.create_window(f"Network Optimizer {settings.APP_VERSION}", url,
                              width=1280, height=840, min_size=(900, 600))
        webview.start()
    except Exception:
        httpd.shutdown()
        return False
    finally:
        try:
            app.monitor.stop()
        except Exception:
            pass
    httpd.shutdown()
    return True
