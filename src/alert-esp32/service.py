"""
Alert Notifier Service for the ESP32 Physical Alert System.

Publishes lightweight severity notifications over MQTT (topic: 'alerts/status')
and handles analyst physical acknowledge events (topic: 'alerts/ack').
"""

from __future__ import annotations

import json
import logging
import threading
from typing import Any, Callable, Optional

try:
    import paho.mqtt.client as mqtt
except ImportError:
    mqtt = None

from src.alert_esp32.models import AlertNotification, AlertAcknowledgeMessage

logger = logging.getLogger(__name__)

TOPIC_STATUS = "alerts/status"
TOPIC_ACK = "alerts/ack"


class AlertNotifierService:
    """Manages MQTT communication between MMS SOC alerting and physical ESP32 devices."""

    def __init__(
        self,
        broker_host: str = "localhost",
        broker_port: int = 1883,
        client_id: str = "mms-alert-notifier",
        on_ack_received: Optional[Callable[[AlertAcknowledgeMessage], None]] = None,
    ) -> None:
        self.broker_host = broker_host
        self.broker_port = broker_port
        self.client_id = client_id
        self.on_ack_received = on_ack_received
        self._client: Optional[Any] = None
        self._connected = False
        self._lock = threading.Lock()
        self._last_notification: Optional[AlertNotification] = None
        self._last_ack: Optional[AlertAcknowledgeMessage] = None

    @property
    def is_connected(self) -> bool:
        return self._connected

    @property
    def last_notification(self) -> Optional[AlertNotification]:
        return self._last_notification

    @property
    def last_ack(self) -> Optional[AlertAcknowledgeMessage]:
        return self._last_ack

    def connect(self) -> bool:
        """Connect to the Mosquitto MQTT broker."""
        if mqtt is None:
            logger.warning("paho-mqtt not available; alert notifier running in mock/offline mode")
            return False

        try:
            # Support both paho-mqtt v1.x and v2.x
            if hasattr(mqtt, "CallbackAPIVersion"):
                self._client = mqtt.Client(
                    callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
                    client_id=self.client_id,
                )
            else:
                self._client = mqtt.Client(client_id=self.client_id)

            self._client.on_connect = self._on_connect
            self._client.on_disconnect = self._on_disconnect
            self._client.on_message = self._on_message

            self._client.connect_async(self.broker_host, self.broker_port, keepalive=60)
            self._client.loop_start()
            logger.info("AlertNotifierService started connecting to MQTT broker at %s:%d", self.broker_host, self.broker_port)
            return True
        except Exception as exc:
            logger.warning("Failed to start MQTT connection to %s:%d: %s", self.broker_host, self.broker_port, exc)
            self._connected = False
            return False

    def disconnect(self) -> None:
        """Disconnect and stop MQTT event loop."""
        if self._client is not None:
            try:
                self._client.loop_stop()
                self._client.disconnect()
            except Exception:
                pass
            finally:
                self._client = None
                self._connected = False

    def notify(self, notification: AlertNotification | dict) -> bool:
        """Publish an alert notification payload to the ESP32."""
        if isinstance(notification, dict):
            notification = AlertNotification.from_alert(notification)

        payload_str = json.dumps(notification.model_dump())
        self._last_notification = notification

        if not self._connected or self._client is None:
            logger.debug("MQTT broker not connected; stored notification locally: %s", payload_str)
            return False

        try:
            res = self._client.publish(TOPIC_STATUS, payload_str, qos=1)
            return res.rc == mqtt.MQTT_ERR_SUCCESS
        except Exception as exc:
            logger.error("Failed to publish alert to MQTT topic %s: %s", TOPIC_STATUS, exc)
            return False

    def notify_from_alert(self, alert_data: dict | object) -> AlertNotification:
        """Helper to construct, sanitize, and publish an alert in one call."""
        notification = AlertNotification.from_alert(alert_data)
        self.notify(notification)
        return notification

    # --- Internal MQTT Callbacks ---

    def _on_connect(self, client: Any, userdata: Any, flags: Any, rc: Any, properties: Any = None) -> None:
        rc_code = getattr(rc, "value", rc)
        if rc_code == 0:
            self._connected = True
            logger.info("Connected to MQTT broker. Subscribing to %s", TOPIC_ACK)
            try:
                client.subscribe(TOPIC_ACK, qos=1)
            except Exception as exc:
                logger.error("Failed to subscribe to %s: %s", TOPIC_ACK, exc)
        else:
            self._connected = False
            logger.warning("MQTT connection failed with code: %s", rc_code)

    def _on_disconnect(self, client: Any, userdata: Any, rc: Any, *args: Any) -> None:
        self._connected = False
        logger.info("Disconnected from MQTT broker.")

    def _on_message(self, client: Any, userdata: Any, message: Any) -> None:
        try:
            payload = json.loads(message.payload.decode("utf-8"))
            logger.info("Received MQTT message on %s: %s", message.topic, payload)
            if message.topic == TOPIC_ACK:
                ack_msg = AlertAcknowledgeMessage(**payload)
                self._last_ack = ack_msg
                if self.on_ack_received:
                    self.on_ack_received(ack_msg)
        except Exception as exc:
            logger.warning("Error processing incoming MQTT message: %s", exc)

