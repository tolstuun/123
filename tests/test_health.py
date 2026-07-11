import os
os.environ.setdefault("DASHBOARD_USERNAME","test")
os.environ.setdefault("DASHBOARD_PASSWORD","test")
from app.main import app

def test_health_route_exists():
    paths={route.path for route in app.routes}
    assert "/health" in paths and "/ready" in paths
