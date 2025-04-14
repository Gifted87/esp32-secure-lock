#include <Arduino.h>
#include "config.h"
#include "drivers/drivers.h"      // Includes all driver namespaces
#include "security/security_utils.h" // Includes all security namespaces
#include "comms/comms.h"        // Includes Comms namespace
#include <ArduinoJson.h>     // For processing commands / building status
#include <esp_log.h>
#include <esp_task_wdt.h>    // Watchdog Timer

// --- Global State ---
enum class SystemState {
    BOOTING,
    IDLE,
    AUTH_RFID_PENDING,
    AUTH_BIO_PENDING,
    AUTH_REMOTE_PENDING, // Command received via MQTT
    UNLOCKING,
    UNLOCKED_TEMP,       // State while lock is open temporarily
    LOCKING,
    ERROR_STATE,
    CONFIG_MODE          // e.g., For enrolling fingerprints via MQTT command
};

SystemState currentState = SystemState::BOOTING;
static const char* TAG = "Main";

// --- Timers ---
TimerHandle_t unlockTimer = NULL;
void unlockTimerCallback(TimerHandle_t xTimer); // Forward declaration

// --- Application Logic ---

// Callback function passed to Comms module to handle validated commands
void handleCommand(const uint8_t* decrypted_payload, size_t length) {
    ESP_LOGI(TAG, "Processing validated command (length: %d)", length);
    StatusIndicator::setPattern(StatusIndicator::Pattern::AUTH_WAITING); // Indicate processing

    // Attempt to parse the payload as JSON
    StaticJsonDocument<256> doc; // Adjust size as needed
    DeserializationError error = deserializeJson(doc, decrypted_payload, length);

    if (error) {
        ESP_LOGE(TAG, "Command JSON deserialization failed: %s", error.c_str());
         // Maybe payload wasn't JSON? Handle raw commands if needed.
         StatusIndicator::setPattern(StatusIndicator::Pattern::AUTH_FAIL);
        return;
    }

    // Process the command based on JSON content
    const char* command = doc["command"];
    if (!command) {
        ESP_LOGE(TAG, "Command JSON missing 'command' field.");
         StatusIndicator::setPattern(StatusIndicator::Pattern::AUTH_FAIL);
        return;
    }

    ESP_LOGI(TAG, "Received command: %s", command);

    if (strcmp(command, "UNLOCK") == 0) {
        if (currentState == SystemState::IDLE || currentState == SystemState::LOCKING) {
             ESP_LOGI(TAG, "Remote UNLOCK command authorized.");
             currentState = SystemState::UNLOCKING;
             // Success indicator handled by state transition
        } else {
             ESP_LOGW(TAG, "Unlock command received but system not in IDLE state (%d).", (int)currentState);
             StatusIndicator::setPattern(StatusIndicator::Pattern::AUTH_FAIL); // Indicate failure/ignore
        }
    } else if (strcmp(command, "LOCK") == 0) {
         if (currentState == SystemState::UNLOCKED_TEMP) {
             ESP_LOGI(TAG, "Remote LOCK command authorized.");
             currentState = SystemState::LOCKING;
             // Stop the unlock timer if it's running
             if (unlockTimer && xTimerIsTimerActive(unlockTimer)) {
                 xTimerStop(unlockTimer, 0);
             }
             // Indicator handled by state transition
         } else {
             ESP_LOGW(TAG, "Lock command received but system not UNLOCKED_TEMP (%d).", (int)currentState);
             StatusIndicator::setPattern(StatusIndicator::Pattern::AUTH_FAIL);
         }
    } else if (strcmp(command, "ENROLL_FINGER") == 0) {
        int id = doc["id"] | -1; // Get ID from JSON, default to -1
        if (id >= 0 && id < Biometrics::finger.capacity) { // Check valid ID range
             ESP_LOGI(TAG, "Entering Fingerprint Enrollment mode for ID %d via remote command.", id);
             currentState = SystemState::CONFIG_MODE;
             // Trigger enrollment process (can be handled in CONFIG_MODE state)
             // Need a way to report success/failure back via MQTT
             Biometrics::enrollFingerprint(id); // This is blocking, consider a non-blocking approach
             // Publish result back after enrollment finishes/fails
             // Comms::publishStatus("enroll", Biometrics::enrollStatus == Biometrics::Status::ENROLL_STEP2_OK ? "success" : "fail");
             currentState = SystemState::IDLE; // Return to idle after enrollment attempt
             StatusIndicator::setPattern(StatusIndicator::Pattern::IDLE_LOCKED); // Reset indicator
        } else {
             ESP_LOGE(TAG, "Invalid or missing ID for ENROLL_FINGER command.");
              StatusIndicator::setPattern(StatusIndicator::Pattern::AUTH_FAIL);
        }
    } else if (strcmp(command, "DELETE_FINGER") == 0) {
         int id = doc["id"] | -1;
         if (id >= 0) {
             ESP_LOGI(TAG, "Deleting fingerprint ID %d via remote command.", id);
             Biometrics::Status delStatus = Biometrics::deleteFingerprint(id);
             Comms::publishStatus("delete", delStatus == Biometrics::Status::DELETE_SUCCESS ? "{\"status\":\"success\"}" : "{\"status\":\"fail\"}");
             StatusIndicator::setPattern(delStatus == Biometrics::Status::DELETE_SUCCESS ? StatusIndicator::Pattern::AUTH_SUCCESS : StatusIndicator::Pattern::AUTH_FAIL);
         } else {
              ESP_LOGE(TAG, "Invalid or missing ID for DELETE_FINGER command.");
               StatusIndicator::setPattern(StatusIndicator::Pattern::AUTH_FAIL);
         }
    } else if (strcmp(command, "STATUS_REQUEST") == 0) {
         ESP_LOGI(TAG,"Status requested via MQTT.");
         // Publish current status
         StaticJsonDocument<128> statusDoc;
         statusDoc["state"] = (int)currentState;
         statusDoc["lock"] = (LockControl::getState() == LockControl::State::LOCKED) ? "locked" : "unlocked";
         statusDoc["timeSynced"] = isTimeSynced();
         statusDoc["templates"] = Biometrics::getTemplateCount();
         char jsonBuffer[128];
         serializeJson(statusDoc, jsonBuffer);
         Comms::publishStatus("current", jsonBuffer);
         StatusIndicator::setPattern(LockControl::getState() == LockControl::State::LOCKED ? StatusIndicator::Pattern::IDLE_LOCKED : StatusIndicator::Pattern::IDLE_UNLOCKED); // Back to idle state
    }
     else {
        ESP_LOGW(TAG, "Unknown command received: %s", command);
         StatusIndicator::setPattern(StatusIndicator::Pattern::AUTH_FAIL);
    }
}

// --- Setup ---
void setup() {
    Serial.begin(SERIAL_BAUD_RATE);
    ESP_LOGI(TAG, "--- Secure IoT Lock System Booting ---");

    // Initialize Watchdog (adjust timeout as needed)
    esp_task_wdt_init(10, true); // 10 seconds timeout, panic on timeout
    esp_task_wdt_add(NULL); // Add current task (setup/loop)

    // Initialize Status LED early for feedback
    if (!StatusIndicator::init(STATUS_LED_PIN, -1, -1)) { // Example: Use built-in LED on GPIO 2 as Red
         ESP_LOGE(TAG, "Failed to initialize Status Indicator!");
         // No visual feedback possible - critical?
    }
    StatusIndicator::setPattern(StatusIndicator::Pattern::SYSTEM_BOOTING);

    // Initialize Security Modules FIRST
    ESP_LOGI(TAG, "Initializing Security Modules...");
    if (!secure_element_init() || !ecdsa_init() || !totp_init() || !aes_engine_init()) {
        ESP_LOGE(TAG, "CRITICAL: Failed to initialize core security components!");
        currentState = SystemState::ERROR_STATE;
        StatusIndicator::setPattern(StatusIndicator::Pattern::ERROR_ATECC); // Specific ATECC error likely
        // Halt or enter safe mode?
        while(1) { delay(1000); esp_task_wdt_reset(); } // Hang here flashing error
    }
    ESP_LOGI(TAG, "Security Modules Initialized.");


    // Initialize Drivers
    ESP_LOGI(TAG, "Initializing Drivers...");
    if (!RFID::init() || !Biometrics::init() || !LockControl::init()) {
         ESP_LOGE(TAG, "CRITICAL: Failed to initialize hardware drivers!");
         currentState = SystemState::ERROR_STATE;
         StatusIndicator::setPattern(StatusIndicator::Pattern::ERROR_GENERIC);
         while(1) { delay(1000); esp_task_wdt_reset(); } // Hang here flashing error
    }
    ESP_LOGI(TAG, "Drivers Initialized.");


    // Initialize Communications (requires WiFi and Security modules)
    ESP_LOGI(TAG, "Initializing Communication Module...");
    if (!Comms::init(handleCommand)) { // Pass the command handler function
        ESP_LOGE(TAG, "Communication module initialization failed (check WiFi/MQTT/TLS config).");
        // Non-critical? System might work offline? Decide behavior.
        // For now, allow continuing but MQTT won't work.
        StatusIndicator::setPattern(StatusIndicator::Pattern::ERROR_MQTT); // Show MQTT error initially
    } else {
         ESP_LOGI(TAG, "Communication Module Initialized.");
    }

    // Create the Unlock Timer (but don't start it yet)
    unlockTimer = xTimerCreate("UnlockTimer",                 // Timer name
                               pdMS_TO_TICKS(UNLOCK_DURATION_MS), // Timer period in ticks
                               pdFALSE,                       // Auto-reload = false (one-shot)
                               (void*)0,                      // Timer ID (not used)
                               unlockTimerCallback);          // Callback function
    if (!unlockTimer) {
         ESP_LOGE(TAG, "Failed to create unlock timer!");
         // Degraded mode - lock won't auto-relock
    }


    ESP_LOGI(TAG, "Setup Complete. Entering Idle State.");
    currentState = SystemState::IDLE;
    StatusIndicator::setPattern(StatusIndicator::Pattern::IDLE_LOCKED); // Assume starting locked
}


// --- Main Loop ---
void loop() {
    // Reset watchdog timer periodically
    esp_task_wdt_reset();

    // Update status indicator animations (blinking/pulsing)
    StatusIndicator::update();

    // Maintain MQTT connection and check for incoming messages
    // This also handles WiFi connection checks internally
    if (!Comms::loop()) {
        // Connection issue, indicator pattern likely set by Comms::loop()
        // Decide if other functions should be blocked if MQTT fails (e.g., require server check for RFID?)
    }

    // --- State Machine ---
    switch (currentState) {
        case SystemState::IDLE:
            // Check for local authentication methods
            // 1. RFID Check
            MFRC522::Uid rfidUid;
            RFID::Status rfidStatus = RFID::checkAndReadCard(rfidUid);
            if (rfidStatus == RFID::Status::READ_OK) {
                 ESP_LOGI(TAG, "RFID Card Detected. UID: [HIDDEN]"); // Log UID carefully or hash it
                 // ** SECURITY: Check UID against allowed list **
                 // This list could be hardcoded (bad), stored in NVS, or fetched from server.
                 // Fetching/caching from server via MQTT is more flexible.
                 // Placeholder: Assume UID 0xDE 0xAD 0xBE 0xEF is allowed
                 byte allowed_uid[] = {0xDE, 0xAD, 0xBE, 0xEF}; // Example
                 if (rfidUid.size == 4 && memcmp(rfidUid.uidByte, allowed_uid, 4) == 0) {
                     ESP_LOGI(TAG,"RFID UID Authorized.");
                     currentState = SystemState::UNLOCKING;
                     StatusIndicator::setPattern(StatusIndicator::Pattern::AUTH_SUCCESS);
                 } else {
                     ESP_LOGW(TAG,"RFID UID Denied.");
                     StatusIndicator::setPattern(StatusIndicator::Pattern::AUTH_FAIL);
                 }
                 RFID::halt(); // De-select card after check
                 delay(500); // Debounce / prevent immediate re-read

            } else if (rfidStatus == RFID::Status::AUTH_FAIL) {
                ESP_LOGW(TAG,"RFID Authentication Failed (Secure Read Attempt).");
                StatusIndicator::setPattern(StatusIndicator::Pattern::AUTH_FAIL);
                RFID::halt();
                delay(500);
            }

            // 2. Biometric Check (only if RFID wasn't successful this loop iteration)
            if (currentState == SystemState::IDLE) { // Check if state changed due to RFID
                int fingerId = -1;
                int confidence = 0;
                Biometrics::Status bioStatus = Biometrics::getFingerprintMatch(fingerId, confidence);

                if (bioStatus == Biometrics::Status::MATCH_SUCCESS) {
                     ESP_LOGI(TAG, "Biometric Match Success. ID: %d, Confidence: %d", fingerId, confidence);
                     // Optionally check confidence level
                     if (confidence > 50) { // Example threshold
                         currentState = SystemState::UNLOCKING;
                         StatusIndicator::setPattern(StatusIndicator::Pattern::AUTH_SUCCESS);
                     } else {
                          ESP_LOGW(TAG,"Biometric match confidence too low (%d).", confidence);
                          StatusIndicator::setPattern(StatusIndicator::Pattern::AUTH_FAIL);
                     }
                     delay(500); // Debounce
                } else if (bioStatus == Biometrics::Status::MATCH_FAIL) {
                    // Normal - no matching finger found
                    // StatusIndicator::setPattern(StatusIndicator::Pattern::AUTH_FAIL); // Don't flash fail constantly
                } else if (bioStatus == Biometrics::Status::SENSOR_ERROR) {
                     ESP_LOGE(TAG, "Biometric Sensor Error.");
                     // Enter error state? Or just log?
                     StatusIndicator::setPattern(StatusIndicator::Pattern::ERROR_GENERIC);
                     currentState = SystemState::ERROR_STATE; // Example: treat sensor error as system error
                }
                // Ignore NO_FINGER state
            }
             // Check for TOTP input if applicable (e.g., keypad - not implemented here)

             // Check for tamper switch (if implemented)
             // if (digitalRead(TAMPER_PIN) == LOW) { /* Handle tamper */ }

            break; // End IDLE state

        case SystemState::UNLOCKING:
            ESP_LOGI(TAG, "State: UNLOCKING");
            LockControl::unlock();
            // Start the timer to automatically relock
            if (unlockTimer) {
                if (xTimerIsTimerActive(unlockTimer)) { xTimerStop(unlockTimer, 0); } // Stop if already active
                if (xTimerStart(unlockTimer, 0) != pdPASS) {
                     ESP_LOGE(TAG, "Failed to start unlock timer!");
                     // Problem: Won't auto-relock. Maybe force lock immediately?
                     currentState = SystemState::LOCKING;
                } else {
                     ESP_LOGI(TAG,"Unlock timer started (%d ms).", UNLOCK_DURATION_MS);
                     currentState = SystemState::UNLOCKED_TEMP;
                     StatusIndicator::setPattern(StatusIndicator::Pattern::IDLE_UNLOCKED);
                     // Publish status update
                     Comms::publishStatus("lock", "{\"state\":\"unlocked\"}");
                }
            } else {
                 ESP_LOGW(TAG,"Unlock timer not available. Manual locking required.");
                 currentState = SystemState::UNLOCKED_TEMP; // Still go to unlocked state
                 StatusIndicator::setPattern(StatusIndicator::Pattern::IDLE_UNLOCKED);
                 Comms::publishStatus("lock", "{\"state\":\"unlocked\"}");
            }
            break;

        case SystemState::UNLOCKED_TEMP:
             // Waiting for timer expiry or manual LOCK command
             // Check if timer expired (handled by callback)
             // Check for manual lock input (e.g., button - not implemented)
             // MQTT LOCK command handled by handleCommand -> sets state to LOCKING
             // ESP_LOGD(TAG, "State: UNLOCKED_TEMP"); // Too noisy
            break;

        case SystemState::LOCKING:
            ESP_LOGI(TAG, "State: LOCKING");
            LockControl::lock();
            currentState = SystemState::IDLE; // Transition back to IDLE
            StatusIndicator::setPattern(StatusIndicator::Pattern::IDLE_LOCKED);
            Comms::publishStatus("lock", "{\"state\":\"locked\"}");
            break;

        case SystemState::CONFIG_MODE:
             ESP_LOGI(TAG, "State: CONFIG_MODE");
             StatusIndicator::setPattern(StatusIndicator::Pattern::CONFIG_MODE);
             // Handle specific config actions, e.g., waiting for enrollment steps
             // If enrollment is blocking (like current Biometrics::enrollFingerprint),
             // the system might be unresponsive here. Consider non-blocking state machine for enrollment.
             delay(100); // Prevent busy-looping if no action
            break;

        case SystemState::ERROR_STATE:
             ESP_LOGE(TAG, "State: ERROR_STATE. System Halted.");
             // Indicator should be flashing error pattern
             // Maybe try to publish error status?
             // Comms::publishStatus("system", "{\"status\":\"error\"}"); // Might fail if MQTT is the error
             delay(1000); // Slow loop in error state
             // Optionally attempt recovery or require reboot
            break;

        default:
            ESP_LOGW(TAG, "Unhandled System State: %d", (int)currentState);
            currentState = SystemState::IDLE; // Recover to IDLE
            StatusIndicator::setPattern(StatusIndicator::Pattern::IDLE_LOCKED);
            break;
    }

    // Small delay to prevent watchdog issues if loop is too fast / add stability
    delay(10); // Adjust as needed
}

// --- Timer Callback ---
void unlockTimerCallback(TimerHandle_t xTimer) {
    ESP_LOGI(TAG, "Unlock timer expired.");
    // Ensure we are still in the temporary unlocked state before locking
    if (currentState == SystemState::UNLOCKED_TEMP) {
         ESP_LOGI(TAG,"Timer initiating auto-lock.");
         currentState = SystemState::LOCKING; // Trigger locking sequence in main loop
    } else {
         ESP_LOGW(TAG,"Unlock timer expired, but system state was not UNLOCKED_TEMP (%d). Not auto-locking.", (int)currentState);
    }
}