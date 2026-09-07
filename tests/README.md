# Integration tests

Run from the project root:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Pytest starts a fresh Flask server process on `127.0.0.1` with an available
port for each test, waits for `/health`, and stops the process afterward.
You do not need to start a server manually. HTTP and WebSocket clients connect
to the same server over real sockets. Tests inspect status codes and JSON
responses without importing the app or accessing its in-memory state.

A fresh process keeps message queues and connections isolated between tests.
Startup failures include the server log; requests and startup have timeouts.
Dependencies are listed in the root `requirements.txt`.
