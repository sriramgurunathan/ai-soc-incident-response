import uvicorn
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

if __name__ == "__main__":
    print("==================================================================")
    print("  APEXSHIELD AI-SOC ENTERPRISE DEFENSE PLATFORM")
    print("  High-Velocity Brute Force & 3-Password History Remediation Engine")
    print("==================================================================")
    print("  [*] Portal & SOC Interface: http://127.0.0.1:8000")
    print("  [*] Swagger API Docs:      http://127.0.0.1:8000/docs")
    print("  [*] Live WebSocket Bus:    ws://127.0.0.1:8000/ws/soc-stream")
    print("==================================================================")
    uvicorn.run("backend.app.main:app", host="127.0.0.1", port=8000, reload=True)
