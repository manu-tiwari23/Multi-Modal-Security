"""
MMS Phase 9 - ESP32 Firmware Flashing & Diagnostic Tool.

Queries and flashes the connected ESP32 dev board over USB serial.
"""

import sys
import subprocess
import serial.tools.list_ports


def find_esp32_port() -> str:
    ports = list(serial.tools.list_ports.comports())
    for p in ports:
        desc = (p.description or "").lower()
        if "cp210" in desc or "ch340" in desc or "ftdi" in desc or "uart" in desc or "serial" in desc:
            return p.device
    if ports:
        return ports[0].device
    return "COM6"


def main():
    port = sys.argv[1] if len(sys.argv) > 1 else find_esp32_port()
    print("=" * 60)
    print("  Multi Modal Security (MMS) - ESP32 Flashing Tool")
    print("=" * 60)
    print(f"Target Serial Port: {port}\n")

    print("[*] Checking ESP32 chip connection...")
    print(">>> NOTE: If connection hangs at 'Connecting...', HOLD the 'BOOT' button")
    print(">>> on your ESP32 board until the connection completes!\n")

    cmd = [sys.executable, "-m", "esptool", "--port", port, "--baud", "115200", "chip-id"]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        print(res.stdout)
        if res.stderr:
            print(res.stderr)
        if res.returncode == 0:
            print("[+] ESP32 detected and communicating successfully!")
        else:
            print("[-] Chip communication failed. Please hold BOOT and run again.")
    except Exception as exc:
        print(f"[-] Execution error: {exc}")


if __name__ == "__main__":
    main()

