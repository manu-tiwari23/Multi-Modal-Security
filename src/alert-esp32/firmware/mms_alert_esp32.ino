/*
 * Multi Modal Security (MMS) - Phase 9 Physical Alert System
 * Hardware: ESP32 Dev Module (WROOM-32)
 *
 * Pin Connections:
 *   - Green LED   -> GPIO 18 (with 220Ω - 330Ω resistor to GND)
 *   - Yellow LED  -> GPIO 19 (with 220Ω - 330Ω resistor to GND)
 *   - Red LED     -> GPIO 21 (with 220Ω - 330Ω resistor to GND)
 *   - Active Buzzer -> GPIO 22 (VCC to 3.3V/5V, I/O to GPIO 22, GND to GND)
 *   - Ack Button  -> GPIO 23 (Push button to GND, uses internal INPUT_PULLUP)
 *
 * MQTT Topics:
 *   - Subscribe:   alerts/status
 *   - Publish ACK: alerts/ack
 */

#include <WiFi.h>
#include "PubSubClient.h"

// ---------------------------------------------------------------------------
// Network & Broker Configuration
// (Update with your Wi-Fi credentials and PC LAN IP running MMS / Mosquitto)
// ---------------------------------------------------------------------------
const char* WIFI_SSID     = "Jujutsu_Kaisen";
const char* WIFI_PASSWORD = "Gojo@2026!";

// IP address of your host machine running the Mosquitto MQTT broker (port 1883)
const char* MQTT_SERVER   = "162.168.1.17";
const int   MQTT_PORT     = 1883;
const char* MQTT_USER     = "";  // Leave blank if anonymous
const char* MQTT_PASS     = "";  // Leave blank if anonymous

const char* TOPIC_STATUS  = "alerts/status";
const char* TOPIC_ACK     = "alerts/ack";
const char* DEVICE_ID     = "esp32-desk-01";

// ---------------------------------------------------------------------------
// GPIO Pin Mapping
// ---------------------------------------------------------------------------
const int PIN_LED_GREEN   = 18;
const int PIN_LED_YELLOW  = 19;
const int PIN_LED_RED     = 21;
const int PIN_BUZZER      = 22;
const int PIN_BTN_ACK     = 23;

// ---------------------------------------------------------------------------
// State Variables
// ---------------------------------------------------------------------------
enum SystemState {
  STATE_NORMAL,
  STATE_LOW_MEDIUM,
  STATE_HIGH,
  STATE_CRITICAL
};

SystemState currentState = STATE_NORMAL;
bool isAcknowledged = false;

WiFiClient espClient;
PubSubClient mqttClient(espClient);

// Timing & Animation Variables
unsigned long lastBlinkToggle = 0;
bool redLedState = false;
unsigned long lastBeepTime = 0;
unsigned long lastBtnCheck = 0;
int lastBtnReading = HIGH;

// ---------------------------------------------------------------------------
// Hardware Control Functions
// ---------------------------------------------------------------------------
void setLeds(bool green, bool yellow, bool red) {
  digitalWrite(PIN_LED_GREEN, green ? HIGH : LOW);
  digitalWrite(PIN_LED_YELLOW, yellow ? HIGH : LOW);
  digitalWrite(PIN_LED_RED, red ? HIGH : LOW);
}

void setBuzzer(bool on) {
  digitalWrite(PIN_BUZZER, on ? HIGH : LOW);
}

void updateAlertHardware() {
  unsigned long now = millis();

  // If critical/high was acknowledged by analyst button press, silence buzzer and stop fast-blinking
  if (isAcknowledged) {
    setLeds(true, false, false);
    setBuzzer(false);
    return;
  }

  switch (currentState) {
    case STATE_NORMAL:
      setLeds(true, false, false); // Green ON, others OFF
      setBuzzer(false);
      break;

    case STATE_LOW_MEDIUM:
      setLeds(false, true, false); // Yellow ON, others OFF
      setBuzzer(false);
      break;

    case STATE_HIGH:
      // Red LED Blinking (slow, 1000ms period)
      if (now - lastBlinkToggle >= 500) {
        lastBlinkToggle = now;
        redLedState = !redLedState;
        digitalWrite(PIN_LED_GREEN, LOW);
        digitalWrite(PIN_LED_YELLOW, LOW);
        digitalWrite(PIN_LED_RED, redLedState ? HIGH : LOW);
      }
      // Short beep every 5 seconds
      if (now - lastBeepTime >= 5000) {
        lastBeepTime = now;
        setBuzzer(true);
        delay(80);
        setBuzzer(false);
      }
      break;

    case STATE_CRITICAL:
      // Red LED Fast Blinking (200ms period)
      if (now - lastBlinkToggle >= 100) {
        lastBlinkToggle = now;
        redLedState = !redLedState;
        digitalWrite(PIN_LED_GREEN, LOW);
        digitalWrite(PIN_LED_YELLOW, LOW);
        digitalWrite(PIN_LED_RED, redLedState ? HIGH : LOW);
        // Continuous tone pattern
        setBuzzer(redLedState);
      }
      break;
  }
}

// ---------------------------------------------------------------------------
// MQTT Message Handler
// ---------------------------------------------------------------------------
void onMqttMessage(char* topic, byte* payload, unsigned int length) {
  String msg = "";
  for (unsigned int i = 0; i < length; i++) {
    msg += (char)payload[i];
  }

  Serial.print("[MMS] Alert Received on [");
  Serial.print(topic);
  Serial.print("]: ");
  Serial.println(msg);

  // Parse lightweight JSON payload
  // Expected shape: {"severity": "critical"|"high"|"medium"|"low"|"normal", "incident_type": "...", ...}
  msg.toLowerCase();

  if (msg.indexOf("\"critical\"") > 0 || msg.indexOf("\"p1\"") > 0) {
    currentState = STATE_CRITICAL;
    isAcknowledged = false;
    Serial.println(">>> POSTURE: CRITICAL ALERT (Red Fast Blink + Continuous Buzzer)");
  } else if (msg.indexOf("\"high\"") > 0 || msg.indexOf("\"p2\"") > 0) {
    currentState = STATE_HIGH;
    isAcknowledged = false;
    Serial.println(">>> POSTURE: HIGH ALERT (Red Slow Blink + Periodic Beep)");
  } else if (msg.indexOf("\"medium\"") > 0 || msg.indexOf("\"low\"") > 0 || msg.indexOf("\"p3\"") > 0) {
    currentState = STATE_LOW_MEDIUM;
    isAcknowledged = false;
    Serial.println(">>> POSTURE: LOW/MEDIUM ALERT (Yellow Solid)");
  } else if (msg.indexOf("\"normal\"") > 0) {
    currentState = STATE_NORMAL;
    isAcknowledged = false;
    Serial.println(">>> POSTURE: NORMAL (Green Solid)");
  }
}

// ---------------------------------------------------------------------------
// Acknowledge Button Check (Debounced)
// ---------------------------------------------------------------------------
void checkAcknowledgeButton() {
  unsigned long now = millis();
  if (now - lastBtnCheck < 50) return; // 50ms debounce window
  lastBtnCheck = now;

  int reading = digitalRead(PIN_BTN_ACK);
  if (reading == LOW && lastBtnReading == HIGH) {
    // Button pressed (Active LOW with internal pull-up)
    Serial.println("[MMS] Physical Acknowledge Button Pressed!");
    isAcknowledged = true;
    setBuzzer(false);
    setLeds(true, false, false); // Immediate silence & green feedback

    // Publish ACK back to platform over MQTT
    if (mqttClient.connected()) {
      char ackPayload[128];
      snprintf(ackPayload, sizeof(ackPayload), "{\"acknowledged\":true,\"device_id\":\"%s\"}", DEVICE_ID);
      mqttClient.publish(TOPIC_ACK, ackPayload, 1);
      Serial.print("[MMS] Published ACK to: ");
      Serial.println(TOPIC_ACK);
    }
  }
  lastBtnReading = reading;
}

// ---------------------------------------------------------------------------
// Network & MQTT Connection Management
// ---------------------------------------------------------------------------
void setupWiFi() {
  delay(10);
  Serial.println();
  Serial.print("[MMS] Connecting to Wi-Fi SSID: ");
  Serial.println(WIFI_SSID);

  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  int tries = 0;
  while (WiFi.status() != WL_CONNECTED && tries < 30) {
    delay(500);
    Serial.print(".");
    tries++;
  }

  if (WiFi.status() == WL_CONNECTED) {
    Serial.println("\n[MMS] Wi-Fi Connected! IP Address: ");
    Serial.println(WiFi.localIP());
  } else {
    Serial.println("\n[MMS] Wi-Fi Connection failed. Retrying in background...");
  }
}

void reconnectMqtt() {
  if (mqttClient.connected()) return;

  Serial.print("[MMS] Connecting to MQTT Broker at ");
  Serial.print(MQTT_SERVER);
  Serial.print(":");
  Serial.println(MQTT_PORT);

  String clientId = String(DEVICE_ID) + "-" + String(random(0xffff), HEX);

  bool connected = false;
  if (strlen(MQTT_USER) > 0) {
    connected = mqttClient.connect(clientId.c_str(), MQTT_USER, MQTT_PASS);
  } else {
    connected = mqttClient.connect(clientId.c_str());
  }

  if (connected) {
    Serial.println("[MMS] MQTT Connected successfully!");
    mqttClient.subscribe(TOPIC_STATUS, 1);
    Serial.print("[MMS] Subscribed to topic: ");
    Serial.println(TOPIC_STATUS);
  } else {
    Serial.print("[MMS] MQTT Connect failed, rc=");
    Serial.println(mqttClient.state());
  }
}

// ---------------------------------------------------------------------------
// Arduino Setup & Main Loop
// ---------------------------------------------------------------------------
void setup() {
  Serial.begin(115200);
  delay(500);

  Serial.println("==================================================");
  Serial.println("  MMS - Physical Alert System (ESP32 Firmware)   ");
  Serial.println("==================================================");

  // Initialize GPIO Pins
  pinMode(PIN_LED_GREEN, OUTPUT);
  pinMode(PIN_LED_YELLOW, OUTPUT);
  pinMode(PIN_LED_RED, OUTPUT);
  pinMode(PIN_BUZZER, OUTPUT);
  pinMode(PIN_BTN_ACK, INPUT_PULLUP);

  // Self-test LED sequence on boot
  Serial.println("[MMS] Running Hardware Self-Test...");
  setLeds(true, false, false); delay(250);
  setLeds(false, true, false); delay(250);
  setLeds(false, false, true); delay(250);
  setBuzzer(true); delay(100); setBuzzer(false);
  setLeds(true, false, false); // Return to steady green

  setupWiFi();

  mqttClient.setServer(MQTT_SERVER, MQTT_PORT);
  mqttClient.setCallback(onMqttMessage);
}

void loop() {
  // Maintain Wi-Fi
  if (WiFi.status() != WL_CONNECTED) {
    static unsigned long lastWifiRetry = 0;
    if (millis() - lastWifiRetry >= 10000) {
      lastWifiRetry = millis();
      WiFi.reconnect();
    }
  }

  // Maintain MQTT
  if (WiFi.status() == WL_CONNECTED && !mqttClient.connected()) {
    static unsigned long lastMqttRetry = 0;
    if (millis() - lastMqttRetry >= 5000) {
      lastMqttRetry = millis();
      reconnectMqtt();
    }
  }

  mqttClient.loop();
  checkAcknowledgeButton();
  updateAlertHardware();
}
