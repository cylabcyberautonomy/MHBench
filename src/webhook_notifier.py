import json
import traceback
import urllib.request
from typing import Literal


class WebhookNotifier:
    def __init__(self, url: str, type: Literal["discord", "slack"]):
        self.url = url
        self.type = type

    def _send(self, message: str):
        payload = {"content": message} if self.type == "discord" else {"text": message}
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            self.url, data=data, headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=10):
            pass

    def notify_start(self, operation: str, env_type: str):
        self._send(f"\U0001f680 *{operation}* started for `{env_type}`")

    def notify_success(self, operation: str, env_type: str, elapsed: float):
        mins, secs = divmod(int(elapsed), 60)
        self._send(f"\u2705 *{operation}* finished for `{env_type}` ({mins}m {secs:02d}s)")

    def notify_error(self, operation: str, env_type: str, elapsed: float, exc: Exception):
        mins, secs = divmod(int(elapsed), 60)
        tb = traceback.format_exc()
        if self.type == "discord":
            tb = tb[-1500:]  # Discord 2000-char content limit
        self._send(
            f"\u274c **{operation}** failed for `{env_type}` ({mins}m {secs:02d}s)\n```\n{tb}\n```"
        )
