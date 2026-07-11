from dataclasses import dataclass
import os


def _bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    database_url: str = os.getenv("DATABASE_URL", "postgresql://vmray:vmray@db:5432/vmray")
    vmray_base_url: str = os.getenv("VMRAY_BASE_URL", "")
    vmray_api_key: str = os.getenv("VMRAY_API_KEY", "")
    vmray_verify_tls: bool = _bool("VMRAY_VERIFY_TLS", True)
    poll_seconds: int = int(os.getenv("VMRAY_POLL_INTERVAL_SECONDS", "300"))
    overlap_hours: int = int(os.getenv("VMRAY_OVERLAP_HOURS", "6"))
    logical_group_max_gap_seconds: int = int(os.getenv("LOGICAL_GROUP_MAX_GAP_SECONDS", "300"))
    logical_group_settling_seconds: int = int(os.getenv("LOGICAL_GROUP_SETTLING_SECONDS", "900"))
    dashboard_username: str = os.getenv("DASHBOARD_USERNAME", "")
    dashboard_password: str = os.getenv("DASHBOARD_PASSWORD", "")
    environment: str = os.getenv("APP_ENV", "production")

    def validate_web(self) -> None:
        if not self.dashboard_username or not self.dashboard_password:
            raise RuntimeError("Dashboard credentials are not configured")

    def validate_collector(self) -> None:
        if not self.vmray_base_url or not self.vmray_api_key:
            raise RuntimeError("VMRay credentials are not configured")
        if self.poll_seconds < 30:
            raise RuntimeError("Poll interval must be at least 30 seconds")


settings = Settings()
