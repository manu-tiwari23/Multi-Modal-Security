---
name: esp32-alert-module
description: Use when implementing or modifying anything under src/alert-esp32/ — the Alert Notifier Service, MQTT broker config, or the ESP32 firmware itself.
---

## Conventions

- The Alert Notifier Service (server-side) publishes **only** `{severity, incident_type, source, timestamp}` to the MQTT topic — never raw logs, IOCs, evidence, or credentials. This is a hard boundary (see `AGENTS.md` guardrails and `ARCHITECTURE.md` §4.10), not something to relax for convenience during debugging.
- MQTT topics: use `alerts/status` for outgoing severity notifications, `alerts/ack` for the ESP32's acknowledge-button messages back to the platform.
- The Mosquitto broker must require authentication; if it's ever reachable beyond localhost/local network, it must use TLS.
- Firmware (Arduino/C++) should be a single `.ino` file (or small set of files) under `src/alert-esp32/firmware/` — keep it simple, this is a small embedded component, not a place to over-engineer.
- LED/buzzer behavior must match the table in `ARCHITECTURE.md` §4.10 exactly (green=normal, yellow=low/medium, red blinking=high, red fast-blink+continuous buzzer=critical until acknowledged).

## Testing Approach

- Unit test (server side): Alert Notifier Service publishes the correct payload shape for a given severity input
- Manual test (hardware): publish a test MQTT message manually (e.g. via `mosquitto_pub`) and confirm the ESP32 responds with correct LED/buzzer behavior
- Manual test: press the acknowledge button, confirm the `alerts/ack` message arrives and the platform marks the alert acknowledged

## Gotchas

- ESP32 Wi-Fi reconnect logic matters — handle dropped connections gracefully (reconnect + resubscribe), don't assume the connection stays up indefinitely.
- Debounce the physical acknowledge button in firmware to avoid duplicate ack messages from a single press.
