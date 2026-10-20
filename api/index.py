import os
import sys
import urllib.parse

# Add project root to sys.path
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from server import app

# Intercept and patch Flask's wsgi_app directly
_original_wsgi_app = app.wsgi_app

def _vercel_wsgi_app(environ, start_response):
    query_string = environ.get("QUERY_STRING", "")
    params = urllib.parse.parse_qs(query_string, keep_blank_values=True)

    if "__path" in params:
        real_path = params.pop("__path")[0]
        if not real_path.startswith("/"):
            real_path = "/" + real_path
        environ["PATH_INFO"] = "/api" + real_path
        environ["QUERY_STRING"] = urllib.parse.urlencode(
            [(k, v) for k, vals in params.items() for v in vals]
        )
    else:
        path_info = environ.get("PATH_INFO", "")
        if path_info and not path_info.startswith("/api/"):
            environ["PATH_INFO"] = "/api" + (path_info if path_info.startswith("/") else "/" + path_info)

    return _original_wsgi_app(environ, start_response)

app.wsgi_app = _vercel_wsgi_app
handler = app
