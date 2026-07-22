import asyncio
import random
from datetime import datetime, timezone
import httpx
from .config import settings


class VMRayClient:
    def __init__(self):
        settings.validate_collector()
        base = settings.vmray_base_url
        if not base.startswith(("http://", "https://")):
            base = "https://" + base
        self.client = httpx.AsyncClient(base_url=base.rstrip("/"), verify=settings.vmray_verify_tls, headers={"Authorization": f"api_key {settings.vmray_api_key}"}, timeout=90, follow_redirects=False)

    async def get(self, path, params=None):
        for attempt in range(5):
            response = await self.client.get(path, params=params)
            if response.status_code not in {408, 429, 500, 502, 503, 504}:
                response.raise_for_status()
                return response
            if attempt == 4:
                response.raise_for_status()
            await asyncio.sleep(min(30, 2 ** attempt) + random.random())

    async def analyses(self, max_id=None):
        params = {"_limit": 50}
        if max_id is not None: params["_max_id"] = max_id
        return (await self.get("/rest/analysis", params=params)).json().get("data", [])

    async def detail(self, analysis_id): return (await self.get(f"/rest/analysis/{analysis_id}")).json()
    async def vtis(self, analysis_id): return (await self.get(f"/rest/analysis/{analysis_id}/vtis")).json()
    async def sample(self, sample_id): return (await self.get(f"/rest/sample/{sample_id}")).json()
    async def submission(self, submission_id): return (await self.get(f"/rest/submission/{submission_id}")).json()
    async def close(self): await self.client.aclose()


def parse_time(value):
    if not value: return None
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
