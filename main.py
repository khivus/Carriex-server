"""Compatibility shim for the Flask server module.

The application code lives in src/app.py, but the test suite and the
expected runtime form import it as the top-level module named ``server``.
"""

from src.app import app

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True,
        threaded=True,
    )
