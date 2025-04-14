#include "drivers.h"
#include "../config.h" // For pin definitions
#include <Adafruit_Fingerprint.h>
#include <esp_log.h>

static const char* TAG = "Biometrics";

// Use Serial2 for the fingerprint sensor
HardwareSerial fingerprintSerial(2);
Adafruit_Fingerprint finger = Adafruit_Fingerprint(&fingerprintSerial);

namespace Biometrics {

    bool init() {
        fingerprintSerial.begin(57600, SERIAL_8N1, FINGERPRINT_RX_PIN, FINGERPRINT_TX_PIN); // Default baud rate for AS608
        ESP_LOGI(TAG, "Fingerprint serial started (RX: %d, TX: %d)", FINGERPRINT_RX_PIN, FINGERPRINT_TX_PIN);

        finger.begin(57600);
        delay(5);
        if (finger.verifyPassword()) {
            ESP_LOGI(TAG, "Fingerprint sensor found!");
        } else {
            ESP_LOGE(TAG, "Did not find fingerprint sensor!");
            return false;
        }

        // Check parameters
        finger.getParameters();
        ESP_LOGI(TAG, "Sensor Parameters:");
        ESP_LOGI(TAG, "  Status: 0x%X", finger.status_reg);
        ESP_LOGI(TAG, "  Sys ID: 0x%X", finger.system_id);
        ESP_LOGI(TAG, "  Capacity: %d", finger.capacity);
        ESP_LOGI(TAG, "  Security level: %d", finger.security_level);
        ESP_LOGI(TAG, "  Device address: 0x%X", finger.device_addr);
        ESP_LOGI(TAG, "  Packet len: %d", finger.packet_len);
        ESP_LOGI(TAG, "  Baud rate: %d", finger.baud_rate);

        // Optional: Set security level (1-5, higher is stricter)
        // finger.setParam(FINGERPRINT_SECPARAM, 3); // Example: Set level 3

        return true;
    }

    // Non-blocking helper to check for finger presence
    Status checkForFinger(int& p) {
         p = finger.getImage();
        switch (p) {
            case FINGERPRINT_OK:
                // ESP_LOGD(TAG, "Image taken");
                return Status::IMAGE_CAPTURED;
            case FINGERPRINT_NOFINGER:
                // ESP_LOGD(TAG, "."); // Too noisy for regular output
                return Status::NO_FINGER;
            case FINGERPRINT_PACKETRECIEVEERR:
                ESP_LOGE(TAG, "Communication error");
                return Status::SENSOR_ERROR;
            case FINGERPRINT_IMAGEFAIL:
                ESP_LOGE(TAG, "Imaging error");
                return Status::SENSOR_ERROR;
            default:
                ESP_LOGE(TAG, "Unknown error: 0x%X", p);
                return Status::SENSOR_ERROR;
        }
    }


    Status getFingerprintMatch(int& matchedId, int& confidence) {
        uint8_t p; // Use local variable for image result

         // 1. Check for finger and capture image
        Status fingerStatus = checkForFinger(p);
        if (fingerStatus != Status::IMAGE_CAPTURED) {
            return fingerStatus; // Return NO_FINGER or SENSOR_ERROR
        }

        // 2. Convert image to feature template (CharBuffer1)
        p = finger.image2Tz(1);
        switch (p) {
            case FINGERPRINT_OK:
                // ESP_LOGD(TAG, "Image converted");
                break;
            case FINGERPRINT_IMAGEMESS:
                ESP_LOGW(TAG, "Image too messy");
                return Status::MATCH_FAIL; // Treat messy image as failure
            case FINGERPRINT_PACKETRECIEVEERR:
                ESP_LOGE(TAG, "Communication error");
                return Status::SENSOR_ERROR;
            case FINGERPRINT_FEATUREFAIL:
            case FINGERPRINT_INVALIDIMAGE:
                ESP_LOGE(TAG, "Could not find fingerprint features");
                return Status::MATCH_FAIL; // Treat feature fail as failure
            default:
                 ESP_LOGE(TAG, "Unknown error: 0x%X", p);
                return Status::SENSOR_ERROR;
        }

        // 3. Search database for match
        p = finger.fingerSearch(); // Searches library for match to template in CharBuffer1
        if (p == FINGERPRINT_OK) {
            // ESP_LOGD(TAG, "Found a print match!");
        } else if (p == FINGERPRINT_PACKETRECIEVEERR) {
            ESP_LOGE(TAG, "Communication error");
            return Status::SENSOR_ERROR;
        } else if (p == FINGERPRINT_NOTFOUND) {
            ESP_LOGD(TAG, "Did not find a match");
            matchedId = -1;
            confidence = 0;
            return Status::MATCH_FAIL;
        } else {
            ESP_LOGE(TAG, "Unknown error: 0x%X", p);
            return Status::SENSOR_ERROR;
        }

        // Found match!
        matchedId = finger.fingerID;
        confidence = finger.confidence;
        ESP_LOGI(TAG, "Found ID #%d with confidence %d", matchedId, confidence);
        return Status::MATCH_SUCCESS;
    }

    // Interactive enrollment process
    Status enrollFingerprint(int id) {
        ESP_LOGI(TAG, "Starting enrollment for ID #%d. Place finger.", id);
        StatusIndicator::setPattern(StatusIndicator::Pattern::CONFIG_MODE); // Indicate waiting

        uint8_t p = -1;
        // Wait for finger
        while ( (p = finger.getImage()) != FINGERPRINT_OK) {
            if (p == FINGERPRINT_NOFINGER) {
                delay(100); // Don't spam checks
            } else {
                 ESP_LOGE(TAG, "Enroll Step 1 Error: 0x%X", p);
                 StatusIndicator::setPattern(StatusIndicator::Pattern::AUTH_FAIL);
                 return Status::ENROLL_FAIL;
            }
        }
        ESP_LOGI(TAG,"Image taken for step 1.");
        StatusIndicator::setPattern(StatusIndicator::Pattern::AUTH_SUCCESS); // Quick flash
        delay(200); // Visual feedback delay

        // Convert image 1
        p = finger.image2Tz(1);
        if (p != FINGERPRINT_OK) { ESP_LOGE(TAG, "Image 1 convert error: 0x%X", p); StatusIndicator::setPattern(StatusIndicator::Pattern::AUTH_FAIL); return Status::ENROLL_FAIL; }

        ESP_LOGI(TAG,"Image 1 converted. Remove finger.");
        StatusIndicator::setPattern(StatusIndicator::Pattern::IDLE_LOCKED); // Indicate waiting removal
        delay(2000); // Wait for removal
        p = 0;
        while (p != FINGERPRINT_NOFINGER) {
            p = finger.getImage();
            delay(100);
        }

        ESP_LOGI(TAG,"Finger removed. Place same finger again for step 2.");
        StatusIndicator::setPattern(StatusIndicator::Pattern::CONFIG_MODE); // Indicate waiting

        // Wait for same finger again
        while ( (p = finger.getImage()) != FINGERPRINT_OK) {
             if (p == FINGERPRINT_NOFINGER) {
                delay(100);
            } else {
                 ESP_LOGE(TAG, "Enroll Step 2 Error: 0x%X", p);
                 StatusIndicator::setPattern(StatusIndicator::Pattern::AUTH_FAIL);
                 return Status::ENROLL_FAIL;
            }
        }
        ESP_LOGI(TAG,"Image taken for step 2.");
        StatusIndicator::setPattern(StatusIndicator::Pattern::AUTH_SUCCESS); // Quick flash
        delay(200); // Visual feedback delay

        // Convert image 2
        p = finger.image2Tz(2);
        if (p != FINGERPRINT_OK) { ESP_LOGE(TAG, "Image 2 convert error: 0x%X", p); StatusIndicator::setPattern(StatusIndicator::Pattern::AUTH_FAIL); return Status::ENROLL_FAIL; }

        ESP_LOGI(TAG,"Image 2 converted. Creating model...");
        // Create model from the two templates
        p = finger.createModel();
         if (p == FINGERPRINT_OK) {
            ESP_LOGI(TAG,"Prints matched!");
        } else if (p == FINGERPRINT_PACKETRECIEVEERR) {
            ESP_LOGE(TAG,"Communication error"); StatusIndicator::setPattern(StatusIndicator::Pattern::AUTH_FAIL); return Status::ENROLL_FAIL;
        } else if (p == FINGERPRINT_ENROLLMISMATCH) {
            ESP_LOGE(TAG,"Fingerprints did not match"); StatusIndicator::setPattern(StatusIndicator::Pattern::AUTH_FAIL); return Status::ENROLL_FAIL;
        } else {
            ESP_LOGE(TAG,"Unknown error: 0x%X", p); StatusIndicator::setPattern(StatusIndicator::Pattern::AUTH_FAIL); return Status::ENROLL_FAIL;
        }

        ESP_LOGI(TAG, "Storing model at ID #%d...", id);
        // Store model
        p = finger.storeModel(id);
        if (p == FINGERPRINT_OK) {
            ESP_LOGI(TAG,"Model stored successfully!");
             StatusIndicator::setPattern(StatusIndicator::Pattern::AUTH_SUCCESS);
             delay(1000); // Show success
            return Status::ENROLL_STEP2_OK; // Final success state
        } else if (p == FINGERPRINT_PACKETRECIEVEERR) {
            ESP_LOGE(TAG,"Communication error");
        } else if (p == FINGERPRINT_BADLOCATION) {
            ESP_LOGE(TAG,"Could not store in that location (ID %d invalid or out of range)", id);
        } else if (p == FINGERPRINT_FLASHERR) {
            ESP_LOGE(TAG,"Error writing to flash");
        } else {
            ESP_LOGE(TAG,"Unknown error: 0x%X", p);
        }
        StatusIndicator::setPattern(StatusIndicator::Pattern::AUTH_FAIL);
        return Status::ENROLL_FAIL;
    }


    Status deleteFingerprint(int id) {
        uint8_t p = finger.deleteModel(id);

        if (p == FINGERPRINT_OK) {
            ESP_LOGI(TAG,"Fingerprint ID #%d deleted", id);
            return Status::DELETE_SUCCESS;
        } else if (p == FINGERPRINT_PACKETRECIEVEERR) {
            ESP_LOGE(TAG,"Communication error"); return Status::SENSOR_ERROR;
        } else if (p == FINGERPRINT_DELETEFAIL) {
            ESP_LOGE(TAG,"Failed to delete ID #%d", id); return Status::DELETE_FAIL;
        } else {
            ESP_LOGE(TAG,"Unknown error: 0x%X", p); return Status::SENSOR_ERROR;
        }
    }

    int getTemplateCount() {
        finger.getTemplateCount();
        return finger.templateCount;
    }

} // namespace Biometrics