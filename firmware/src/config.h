#ifndef CONFIG_H
#define CONFIG_H

#include <pgmspace.h>

// -- WiFi Settings --
#define WIFI_SSID "Your_WiFi_SSID"
#define WIFI_PASSWORD "Your_WiFi_Password"

// -- MQTT Settings --
#define MQTT_SERVER "your_mqtt_broker.com" // e.g., AWS IoT endpoint, HiveMQ Cloud URL
#define MQTT_PORT 8883
#define MQTT_USER "" // Often handled by client certs, leave blank if not needed
#define MQTT_PASSWORD "" // Often handled by client certs, leave blank if not needed
#define MQTT_CLIENT_ID "ESP32_SecureLock_01" // Must be unique per device
#define MQTT_COMMAND_TOPIC "lock/01/command"
#define MQTT_STATUS_TOPIC "lock/01/status"
#define MQTT_HEARTBEAT_TOPIC "lock/01/heartbeat"
#define MQTT_HEARTBEAT_INTERVAL_MS 60000 // 1 minute

// -- Security Settings --
// ATECC608A Configuration (Assuming I2C)
#define ATECC608A_I2C_ADDRESS 0x60 // Default ATECC608A address
#define ATECC608A_DEVICE_PRIVATE_KEY_SLOT 0 // Slot storing the device's private key for TLS/ECDSA
#define ATECC608A_DEVICE_CERT_SLOT 10       // Slot storing device certificate data (or use filesystem)
#define ATECC608A_SIGNER_CA_PUBLIC_KEY_SLOT 12 // Slot storing the public key of the CA that signed the device cert
#define ATECC608A_SERVER_PUBLIC_KEY_SLOT 13 // Slot storing the public key of the command server (for signature verification)
#define ATECC608A_TOTP_SECRET_SLOT 5      // Slot to store the shared TOTP secret (HMAC key)
#define ATECC608A_RFID_KEY_SLOT 6         // Slot to store the MIFARE Classic Key A/B

// TOTP Settings
#define TOTP_TIME_STEP 30       // TOTP code valid duration in seconds (standard)
#define TOTP_WINDOW 1           // Allow current, previous, and next code (1 = +/- 30s)

// AES Payload Encryption Settings
// **IMPORTANT**: This key MUST be securely provisioned and match the server/receiver.
// Consider deriving this from ATECC608A or storing in its secure memory.
// For demonstration, using a placeholder. NEVER hardcode production keys like this.
#define AES_PAYLOAD_KEY {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, \
                         0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, \
                         0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, \
                         0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
#define AES_KEY_SIZE 256 // bits

// TLS Certificates (Stored in ATECC608A or Filesystem)
// If using filesystem (LittleFS/SPIFFS), define paths:
// #define CA_CERT_PATH "/ca.pem"
// #define CLIENT_CERT_PATH "/client.crt"
// #define CLIENT_KEY_PATH "/client.key" // NOTE: Storing private key in filesystem is insecure! Use ATECC608A.

// Example Root CA (Amazon Root CA 1) - Replace with your broker's CA
// Store this in ATECC608A slot or filesystem (e.g., /ca.pem)
const char* ROOT_CA_PEM_PLACEHOLDER = \
"-----BEGIN CERTIFICATE-----\n" \
"MIIDQTCCAimgAwIBAgITBmyfz5m/jAo54vB4ikPmljZbyjANBgkqhkiG9w0BAQsF\n" \
"ADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6\n" \
// ... rest of CA certificate ...
"-----END CERTIFICATE-----\n";

// -- Hardware Pins --
// RFID MFRC522 (SPI)
#define RFID_SDA_PIN 5  // MOSI
#define RFID_SCK_PIN 18 // SCK
#define RFID_MISO_PIN 19 // MISO
#define RFID_RST_PIN 22 // RST

// Fingerprint Sensor (UART2) - Example pins
#define FINGERPRINT_RX_PIN 16
#define FINGERPRINT_TX_PIN 17

// Lock Mechanism (Relay/Servo)
#define LOCK_PIN 23 // Example GPIO for lock control

// Status LED
#define STATUS_LED_PIN 2 // Built-in LED often on GPIO 2

// Tamper Detection Pin (Optional)
// #define TAMPER_PIN 4

// -- System Behavior --
#define SERIAL_BAUD_RATE 115200
#define UNLOCK_DURATION_MS 5000 // How long the lock stays open

#endif // CONFIG_H