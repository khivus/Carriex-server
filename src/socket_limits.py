"""Bound both complete-frame queues and socket write time before the upgrade."""
from collections import deque
from threading import Lock

from simple_websocket import Server

from src.security import RateLimiter


class PendingFrames:
    def __init__(self, count, maximum_bytes, rate, byte_rate):
        self.frames = deque()
        self.bytes = 0
        self.lock = Lock()
        self.count = count
        self.maximum_bytes = maximum_bytes
        self.rate, self.byte_rate = rate, byte_rate
        self.budgets = RateLimiter(capacity=2)

    def append(self, value):
        size = len(value.encode("utf-8")) if isinstance(value, str) else len(value)
        with self.lock:
            if len(self.frames) >= self.count or self.bytes + size > self.maximum_bytes:
                raise OverflowError("Too many buffered WebSocket messages")
            if self.budgets.consume("messages", "socket", self.rate) or self.budgets.consume("bytes", "socket", self.byte_rate, size):
                raise OverflowError("WebSocket message rate exceeded")
            self.frames.append((value, size))
            self.bytes += size

    def pop(self, index=0):
        if index != 0:
            raise IndexError(index)
        with self.lock:
            value, size = self.frames.popleft()
            self.bytes -= size
            return value

    def __len__(self):
        with self.lock:
            return len(self.frames)


class DeadlineSocket:
    def __init__(self, sock, seconds=5):
        self.socket = sock
        self.lock = Lock()
        self.seconds = seconds
        sock.settimeout(seconds)

    def send(self, data):
        if not self.lock.acquire(timeout=self.seconds):
            raise TimeoutError("Slow WebSocket consumer")
        try:
            self.socket.sendall(data)
            return len(data)
        finally:
            self.lock.release()

    def __getattr__(self, name):
        return getattr(self.socket, name)


class BoundedServer(Server):
    def __init__(self, environ, limits, **kwargs):
        self.limits = limits
        super().__init__(environ, **kwargs)

    @property
    def input_buffer(self):
        return self._pending

    @input_buffer.setter
    def input_buffer(self, _):
        # Base.__init__ assigns the queue before it starts the receiver thread.
        self._pending = PendingFrames(self.limits["WS_PENDING_LIMIT"], self.limits["WS_PENDING_BYTES"],
                                      self.limits["WS_MESSAGE_RATE"], self.limits["WS_BYTE_RATE"])

    @property
    def sock(self):
        return self._socket

    @sock.setter
    def sock(self, value):
        self._socket = DeadlineSocket(value)

    def _handle_events(self):
        try:
            return super()._handle_events()
        except OverflowError:
            try:
                self.close(reason=1008, message="WebSocket resource limit exceeded")
            finally:
                self.connected = False
                self.event.set()
            return False
