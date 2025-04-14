#include "comms.h"
#include "../config.h"
#include "../security/security_utils.h" // For AES, ECDSA, ATECC helpers
#include <WiFi.h>
#include <WiFiClientSecure.h> // For TLS
#include <PubSubClient.h>    // MQTT Client
#include <ArduinoJson.h>     // For parsing/creating status messages
#include <esp_log.h>
#include <mbedtls/pk.h>      // For TLS key context

// ATECC608A mbedTLS hook support (conditional compilation)
// #define ENABLE_ATECC_MBEDTLS_HOOKS // Define this here or in build_flags if attempting ATECC TLS integration
#ifdef ENABLE_ATECC_MBEDTLS_HOOKS
    #include <atca_mbedtls_pk.h> // Required header for ATECC mbedTLS PK hooks
    extern mbedtls_pk_context* get_atecc_mbedtls_key_ctx(); // From ecdsa.cpp
    extern bool setup_atecc_mbedtls_key(); // From ecdsa.cpp
#endif // ENABLE_ATECC_MBEDTLS_HOOKS


static const char* TAG = "MQTT_TLS";

// WiFi Client Secure (handles TLS)
WiFiClientSecure espClient;
// MQTT Client
PubSubClient mqttClient(espClient);

// State Variables
static Comms::Status currentStatus = Comms::Status::DISCONNECTED;
static unsigned long lastReconnectAttempt = 0;
static const long reconnectInterval = 5000; // Try reconnecting every 5 seconds
static Comms::CommandCallback commandCallback = nullptr; // Pointer to the function handling validated commands
static uint8_t aes_key[32]; // Buffer for the AES payload key

// Buffers for MQTT messages (adjust size as needed)
#define MQTT_MSG_BUFFER_SIZE 512
static uint8_t incomingBuffer[MQTT_MSG_BUFFER_SIZE];
static uint8_t outgoingBuffer[MQTT_MSG_BUFFER_SIZE];

// Forward declaration for the internal callback
void mqttCallbackInternal(char* topic, byte* payload, unsigned int length);

// --- Helper Functions ---

bool loadCertificates() {
    ESP_LOGI(TAG, "Configuring TLS Certificates...");

    // 1. Load Root CA
    // Option A: From PEM string in config.h (less secure, easy for demo)
    // espClient.setCACert(ROOT_CA_PEM_PLACEHOLDER);
    // Option B: From Filesystem (e.g., LittleFS/SPIFFS) - Requires filesystem init
    // File caFile = LittleFS.open(CA_CERT_PATH, "r");
    // if (!caFile) { ESP_LOGE(TAG, "Failed to open CA cert file"); return false; }
    // String caPem = caFile.readString();
    // caFile.close();
    // espClient.setCACert(caPem.c_str());
    // Option C: From ATECC608A (Most Secure - Requires reading cert data)
    // ** This is complex: Need to read cert data potentially in chunks **
    // uint8_t cert_buffer[1024]; // Adjust size
    // size_t cert_len = sizeof(cert_buffer);
    // if (!readCertDataFromSlot(ATECC608A_SIGNER_CA_PUBLIC_KEY_SLOT?, cert_buffer, cert_len)) { // Need correct slot for CA
    //    ESP_LOGE(TAG, "Failed to read CA cert from ATECC608A");
    //    return false;
    // }
    // espClient.setCACertRaw(cert_buffer, cert_len); // Use Raw if DER format, or setCACert if PEM
    // --- Using PEM placeholder for now ---
    ESP_LOGI(TAG,"Setting Root CA Cert from placeholder...");
    espClient.setCACert(ROOT_CA_PEM_PLACEHOLDER); // Use placeholder from config.h


    // 2. Load Device Certificate
    // Option A: From Filesystem
    // File clientCertFile = LittleFS.open(CLIENT_CERT_PATH, "r");
    // // ... read and set espClient.setCertificate(clientCert.c_str()); ...
    // Option B: From ATECC608A (Most Secure)
    // ** Complex: Read cert data (DER or PEM format expected by WiFiClientSecure) **
    // uint8_t dev_cert_buf[1024]; size_t dev_cert_len = sizeof(dev_cert_buf);
    // if(readCertDataFromSlot(ATECC608A_DEVICE_CERT_SLOT, dev_cert_buf, dev_cert_len)) {
    //      // ESP WiFiClientSecure likely expects PEM. ATECC stores DER. Conversion needed.
    //      // OR: check if espClient.setCertificateRaw() exists and works with DER.
    //      ESP_LOGW(TAG, "Loading device cert from ATECC: Requires format conversion or Raw support!");
    //      // espClient.setCertificateRaw(dev_cert_buf, dev_cert_len); // Hypothetical
    // } else { ESP_LOGE(TAG, "Failed to read device cert from ATECC"); return false; }
    // --- Placeholder: Assuming certs might be on filesystem or handled externally for now ---
     ESP_LOGW(TAG, "Device certificate loading not implemented! Assuming server-only auth or external provisioning.");
    // If using mutual auth, device cert is needed here.


    // 3. Load Device Private Key
    // Option A: From Filesystem (INSECURE!)
    // File clientKeyFile = LittleFS.open(CLIENT_KEY_PATH, "r");
    // // ... read and set espClient.setPrivateKey(clientKey.c_str()); ...
    // Option B: Using ATECC608A mbedTLS Hooks (Most Secure)
    #ifdef ENABLE_ATECC_MBEDTLS_HOOKS
        ESP_LOGI(TAG, "Setting up ATECC608A private key for mbedTLS...");
        if (!setup_atecc_mbedtls_key()) {
             ESP_LOGE(TAG, "Failed to setup ATECC mbedTLS key context!");
             return false;
        }
        mbedtls_pk_context* pk_ctx = get_atecc_mbedtls_key_ctx();
        if (!pk_ctx) {
             ESP_LOGE(TAG, "Failed to get ATECC mbedTLS key context!");
             return false;
        }
        // Link the ATECC key context to the WiFiClientSecure instance
        espClient.setPrivateKeyCtx(pk_ctx);
        ESP_LOGI(TAG, "ATECC608A Private Key context linked to WiFiClientSecure.");
    #else
        ESP_LOGW(TAG, "Device private key loading not implemented! ATECC Hooks disabled. Assuming server-only auth or insecure key file.");
        // If using mutual auth without ATECC hooks, private key must be loaded here (e.g., from file - risky)
    #endif


    // Optional: Set specific TLS ciphersuites (example for high security)
    // const int ciphersuite_list[] = { MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, 0 }; // Example
    // espClient.setCipherSuites(ciphersuite_list);

    // Optional: Set TLS version (e.g., force TLS 1.2+)
    // espClient.setInsecure(false); // Ensure certificate validation is ON
    // espClient.setHandshakeTimeout(60); // seconds

    ESP_LOGI(TAG,"TLS Certificates configuration attempted.");
    return true; // Return true even if some parts are placeholders for now
}


bool connectWiFi() {
    if (WiFi.status() == WL_CONNECTED) {
        return true;
    }
    ESP_LOGI(TAG, "Attempting WiFi connection to SSID: %s", WIFI_SSID);
    StatusIndicator::setPattern(StatusIndicator::Pattern::SYSTEM_BOOTING); // Indicate connection attempt

    WiFi.mode(WIFI_STA);
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

    unsigned long startAttemptTime = millis();
    while (WiFi.status() != WL_CONNECTED && millis() - startAttemptTime < 15000) { // 15 second timeout
        delay(500);
        Serial.print(".");
    }
    Serial.println();

    if (WiFi.status() == WL_CONNECTED) {
        ESP_LOGI(TAG, "WiFi Connected! IP Address: %s", WiFi.localIP().toString().c_str());
         // Once WiFi is up, sync NTP time
        if (!isTimeSynced()) {
            syncNTPTime(); // From totp.cpp
        }
        return true;
    } else {
        ESP_LOGE(TAG, "WiFi Connection Failed!");
        StatusIndicator::setPattern(StatusIndicator::Pattern::ERROR_GENERIC); // Indicate WiFi failure
        return false;
    }
}

bool reconnectMQTT() {
    if (mqttClient.connected()) {
        return true;
    }
    if (!connectWiFi()) { // Ensure WiFi is up first
        currentStatus = Comms::Status::CONNECTION_FAILED;
        return false;
    }

    ESP_LOGI(TAG, "Attempting MQTT connection to %s:%d...", MQTT_SERVER, MQTT_PORT);
    currentStatus = Comms::Status::CONNECTING;
    StatusIndicator::setPattern(StatusIndicator::Pattern::SYSTEM_BOOTING); // Indicate connection attempt

    mqttClient.setServer(MQTT_SERVER, MQTT_PORT);
    mqttClient.setCallback(mqttCallbackInternal);
    mqttClient.setBufferSize(MQTT_MSG_BUFFER_SIZE); // Ensure buffer is large enough

    // Attempt to connect
    // Note: Client ID must be unique
    bool result = false;
    if (strlen(MQTT_USER) > 0) { // Check if username/password auth is needed
         result = mqttClient.connect(MQTT_CLIENT_ID, MQTT_USER, MQTT_PASSWORD);
    } else { // Assume certificate-based auth
        result = mqttClient.connect(MQTT_CLIENT_ID);
    }

    if (result) {
        ESP_LOGI(TAG, "MQTT Connected!");
        currentStatus = Comms::Status::CONNECTED;
        StatusIndicator::setPattern(StatusIndicator::Pattern::IDLE_LOCKED); // Or current lock state

        // Subscribe to the command topic
        if (mqttClient.subscribe(MQTT_COMMAND_TOPIC)) {
            ESP_LOGI(TAG, "Subscribed to command topic: %s", MQTT_COMMAND_TOPIC);
        } else {
            ESP_LOGE(TAG, "Failed to subscribe to command topic!");
             currentStatus = Comms::Status::MQTT_ERROR;
             return false;
        }
        // Optional: Subscribe to other topics if needed (e.g., config updates)

        // Publish a "connected" status message (optional)
        publishStatus("system", "{\"status\":\"connected\", \"ip\":\"" + WiFi.localIP().toString() + "\"}");

        return true;
    } else {
        ESP_LOGE(TAG, "MQTT Connection Failed, rc=%d. State: %d", mqttClient.state(), espClient.lastError());
        // Print detailed TLS error if available
        char lastErrorBuffer[100];
        espClient.lastError(lastErrorBuffer, sizeof(lastErrorBuffer));
        ESP_LOGE(TAG, "WiFiClientSecure Last Error: %s", lastErrorBuffer);

        currentStatus = Comms::Status::CONNECTION_FAILED;
        StatusIndicator::setPattern(StatusIndicator::Pattern::ERROR_MQTT);
        return false;
    }
}


// --- Internal MQTT Callback ---
// Handles incoming messages, performs security checks, decrypts, and calls the application callback.
void mqttCallbackInternal(char* topic, byte* payload, unsigned int length) {
    ESP_LOGI(TAG, "Message arrived [%s] length: %d", topic, length);
    StatusIndicator::setPattern(StatusIndicator::Pattern::AUTH_WAITING); // Indicate processing

    if (length == 0 || length > MQTT_MSG_BUFFER_SIZE) {
        ESP_LOGE(TAG, "Invalid payload length: %d", length);
         StatusIndicator::setPattern(StatusIndicator::Pattern::AUTH_FAIL); // Treat as failure
        return;
    }

    // Assuming payload format: [ECDSA Signature (64 bytes)][AES Encrypted Data (IV + Ciphertext)]
    // Adjust this based on the actual protocol defined with the server.

    // 1. Check minimum length (Signature + IV + min 1 block AES)
    if (length < 64 + 16 + 16) {
        ESP_LOGE(TAG, "Payload too short for Signature+IV+Data. Length: %d", length);
        StatusIndicator::setPattern(StatusIndicator::Pattern::AUTH_FAIL);
        return;
    }

    // 2. Extract Signature and Ciphertext_with_IV
    const uint8_t* signature = payload;
    const uint8_t* ciphertext_with_iv = payload + 64;
    size_t ciphertext_len = length - 64;

    // 3. Verify Signature using ECDSA (ATECC608A)
    // The signature should be over the *ciphertext_with_iv* part.
    ESP_LOGD(TAG, "Verifying signature over %d bytes of ciphertext...", ciphertext_len);
    if (!verifySignature(ciphertext_with_iv, ciphertext_len, signature, 64)) {
        // SECURITY: Log the breach attempt!
        ESP_LOGW(TAG, "!!! ECDSA Signature Verification FAILED for incoming command on topic %s !!!", topic);
        // Optionally publish a security alert message
        // publishRaw("lock/01/alert", "{\"event\":\"invalid_signature\"}", false);
        StatusIndicator::setPattern(StatusIndicator::Pattern::AUTH_FAIL);
        return; // Discard message
    }
    ESP_LOGI(TAG, "ECDSA Signature VERIFIED for incoming command.");


    // 4. Decrypt Payload using AES Engine (Hardware Accelerated)
    size_t decrypted_len = 0;
    // Reuse incoming buffer temporarily for decrypted output (ensure size is sufficient)
    if (!decryptPacket(ciphertext_with_iv, ciphertext_len, aes_key, AES_KEY_SIZE, incomingBuffer, sizeof(incomingBuffer), decrypted_len)) {
        ESP_LOGE(TAG, "AES Decryption FAILED for incoming command!");
         StatusIndicator::setPattern(StatusIndicator::Pattern::AUTH_FAIL);
        return; // Discard message
    }
    ESP_LOGI(TAG, "AES Decryption successful. Decrypted length: %d", decrypted_len);

    // Temporarily null-terminate for logging (if expecting text)
    // Be cautious if the decrypted data might contain null bytes itself.
    // char* decrypted_text = (char*)incomingBuffer;
    // if (decrypted_len < sizeof(incomingBuffer)) {
    //     decrypted_text[decrypted_len] = '\0';
    //     ESP_LOGD(TAG, "Decrypted Payload: %s", decrypted_text);
    // } else {
    //      ESP_LOGD(TAG, "Decrypted Payload (binary - not null terminated)");
    // }


    // 5. Pass Decrypted Payload to Application Callback
    if (commandCallback != nullptr) {
        ESP_LOGD(TAG, "Calling application command callback...");
        commandCallback(incomingBuffer, decrypted_len);
        // Assume callback handles success/failure indication
    } else {
        ESP_LOGW(TAG, "No command callback registered to handle decrypted message!");
        StatusIndicator::setPattern(StatusIndicator::Pattern::AUTH_FAIL); // Indicate unhandled command
    }

     // Reset indicator to idle after processing (or callback should set final state)
     // StatusIndicator::setPattern(LockControl::getState() == LockControl::State::LOCKED ? StatusIndicator::Pattern::IDLE_LOCKED : StatusIndicator::Pattern::IDLE_UNLOCKED);
}


// --- Public API ---

namespace Comms {

    bool init(CommandCallback cmdCallback) {
        ESP_LOGI(TAG, "Initializing Communications Module...");
        commandCallback = cmdCallback; // Register the callback function

        // Initialize security modules needed by comms
        if (!secure_element_init() || !ecdsa_init() || !aes_engine_init()) {
             ESP_LOGE(TAG, "Failed to initialize underlying security modules!");
             currentStatus = Status::MQTT_ERROR; // Indicate config error
             return false;
        }

        // Load the AES payload key from ATECC608A or other secure storage
        // Placeholder: Use key from config.h (INSECURE FOR PRODUCTION)
        const uint8_t key_placeholder[] = AES_PAYLOAD_KEY;
        memcpy(aes_key, key_placeholder, sizeof(aes_key));
        ESP_LOGW(TAG, "AES Payload Key loaded from insecure placeholder!");
        // TODO: Replace with secure loading, e.g.:
        // if (!readSecretFromSlot(ATECC608A_AES_PAYLOAD_KEY_SLOT, aes_key, sizeof(aes_key))) {
        //     ESP_LOGE(TAG, "Failed to load AES Payload key!");
        //     return false;
        // }

        // Load TLS Certificates and Keys (critical for secure connection)
        if (!loadCertificates()) {
             ESP_LOGE(TAG, "Failed to load TLS certificates/keys!");
             // Continue initialization but connection will likely fail
             // return false; // Strict: fail init if certs fail
        }

        connect(); // Initial connection attempt
        return true;
    }

    void connect() {
         if (currentStatus != Status::CONNECTED) {
             lastReconnectAttempt = 0; // Force immediate reconnect attempt in loop()
             loop(); // Trigger connection logic
         }
    }

    bool loop() {
        if (!connectWiFi()) {
            // Handled in connectWiFi
            return false;
        }

        if (!mqttClient.connected()) {
            unsigned long now = millis();
            if (now - lastReconnectAttempt > reconnectInterval) {
                lastReconnectAttempt = now;
                // Attempt to reconnect
                if (reconnectMQTT()) {
                    lastReconnectAttempt = 0; // Reset timer on success
                } else {
                     // Failure handled in reconnectMQTT
                     return false;
                }
            }
        } else {
            // Client is connected, maintain connection and process messages
            if (!mqttClient.loop()) {
                ESP_LOGE(TAG, "MQTT loop failed. State: %d. Disconnecting.", mqttClient.state());
                 currentStatus = Status::MQTT_ERROR;
                 StatusIndicator::setPattern(StatusIndicator::Pattern::ERROR_MQTT);
                 mqttClient.disconnect();
                 lastReconnectAttempt = millis(); // Schedule immediate reconnect attempt
                 return false;
            }
        }
        return mqttClient.connected();
    }

    Status getStatus() {
        // Update status based on client state if necessary
        if (!mqttClient.connected() && currentStatus == Status::CONNECTED) {
             currentStatus = Status::DISCONNECTED; // Reflect disconnection
        }
         if (WiFi.status() != WL_CONNECTED && currentStatus != Status::CONNECTION_FAILED) {
             currentStatus = Status::CONNECTION_FAILED; // WiFi lost
         }
        return currentStatus;
    }

    // Publish status securely (Encrypt + Sign)
    bool publishStatus(const char* subtopic, const char* message) {
        if (!mqttClient.connected()) {
            ESP_LOGW(TAG, "Cannot publish status, MQTT not connected.");
            return false;
        }

        ESP_LOGD(TAG, "Publishing status to %s/%s: %s", MQTT_STATUS_TOPIC, subtopic, message);

        size_t message_len = strlen(message);
        size_t encrypted_len = 0;
        uint8_t signature[64];
        size_t signature_len = sizeof(signature);

        // 1. Encrypt the message payload
        // Output buffer needs space for IV + encrypted data
        if (!encryptPacket((const uint8_t*)message, message_len, aes_key, AES_KEY_SIZE, outgoingBuffer, sizeof(outgoingBuffer), encrypted_len)) {
            ESP_LOGE(TAG, "Failed to encrypt status message!");
            return false;
        }
        // outgoingBuffer now contains [IV (16 bytes)][Encrypted Data]

        // 2. Sign the *encrypted* payload (IV + Ciphertext)
        if (!signData(outgoingBuffer, encrypted_len, signature, signature_len) || signature_len != 64) {
             ESP_LOGE(TAG, "Failed to sign encrypted status message!");
             return false;
        }
        // signature now contains the 64-byte ECDSA signature

        // 3. Construct the final MQTT payload: [Signature][Encrypted Payload]
        // Need a temporary buffer to combine them if outgoingBuffer was used directly for encryption output
        uint8_t finalPayload[MQTT_MSG_BUFFER_SIZE];
        if (sizeof(finalPayload) < signature_len + encrypted_len) {
             ESP_LOGE(TAG, "Final payload buffer too small!");
            return false;
        }
        memcpy(finalPayload, signature, signature_len);
        memcpy(finalPayload + signature_len, outgoingBuffer, encrypted_len);
        size_t finalPayloadLen = signature_len + encrypted_len;


        // 4. Publish the combined payload
        char fullTopic[128];
        snprintf(fullTopic, sizeof(fullTopic), "%s/%s", MQTT_STATUS_TOPIC, subtopic);

        if (mqttClient.publish(fullTopic, finalPayload, finalPayloadLen)) {
            ESP_LOGD(TAG, "Secure status published successfully to %s (%d bytes)", fullTopic, finalPayloadLen);
            return true;
        } else {
            ESP_LOGE(TAG, "Failed to publish secure status to %s", fullTopic);
            return false;
        }
    }

     // Publish raw, unencrypted data
    bool publishRaw(const char* topic, const char* payload, bool retained) {
         if (!mqttClient.connected()) {
            ESP_LOGW(TAG, "Cannot publish raw data, MQTT not connected.");
            return false;
        }
         ESP_LOGD(TAG, "Publishing raw to %s: %s", topic, payload);
        if (mqttClient.publish(topic, (const uint8_t*)payload, strlen(payload), retained)) {
             return true;
        } else {
             ESP_LOGE(TAG, "Failed to publish raw data to %s", topic);
             return false;
        }
    }


} // namespace Comms