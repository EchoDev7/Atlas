import json
from datetime import datetime

from backend.routers.openvpn import openvpn_manager


def main() -> int:
    started_at = datetime.utcnow().isoformat() + "Z"
    print(f"[health-check] started_at={started_at}")

    health = openvpn_manager.get_runtime_health()
    print(json.dumps(health, indent=2, ensure_ascii=False))

    healthy = bool(health.get("healthy"))
    print(f"[health-check] healthy={healthy}")
    return 0 if healthy else 1


if __name__ == "__main__":
    raise SystemExit(main())
