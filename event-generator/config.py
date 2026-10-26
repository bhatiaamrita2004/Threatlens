"""Configuration for the synthetic event generator.

All IP addresses come from reserved documentation ranges (RFC 5737), so the
data cannot be mistaken for real traffic.
"""

from pathlib import Path

SEED = 42

BASE_DIR = Path(__file__).resolve().parent.parent
RAW_DATA_DIR = BASE_DIR / "data" / "raw"

# Synthetic users U101..U120
USERS = [f"U{100 + i}" for i in range(1, 21)]

# Internal hosts (192.0.2.0/24, TEST-NET-1)
INTERNAL_IPS = [f"192.0.2.{i}" for i in range(10, 60)]
# Normal client addresses (198.51.100.0/24, TEST-NET-2)
CLIENT_IPS = [f"198.51.100.{i}" for i in range(1, 255)]
# Attacker-like source (203.0.113.0/24, TEST-NET-3)
ATTACKER_IP = "203.0.113.50"

LOCATIONS = ["site-A", "site-B", "remote-vpn"]
COMMON_PORTS = [22, 25, 53, 80, 443, 3306, 8080]