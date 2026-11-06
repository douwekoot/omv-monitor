import json
import urllib.error
import urllib.parse
import urllib.request
from urllib.request import urlopen


class PromError(Exception):
    pass


class PromClient:
    def __init__(self, base_url="http://127.0.0.1:9090", timeout=5.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _get(self, path, params):
        url = f"{self.base_url}{path}?{urllib.parse.urlencode(params)}"
        try:
            with urlopen(url, timeout=self.timeout) as resp:
                body = json.load(resp)
        except (urllib.error.URLError, OSError, ValueError) as e:  # HTTPError is a URLError
            raise PromError(str(e)) from e
        if not isinstance(body, dict) or body.get("status") != "success":
            raise PromError(str(body.get("error", body)) if isinstance(body, dict) else "bad response")
        return body["data"]["result"]

    def query(self, expr):
        return self._get("/api/v1/query", {"query": expr})

    def query_range(self, expr, start, end, step):
        return self._get("/api/v1/query_range", {"query": expr, "start": start, "end": end, "step": step})
