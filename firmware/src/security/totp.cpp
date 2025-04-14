#include "security_utils.h"
#include "../config.h"
#include <NTPClient.h>
#include <WiFiUdp.h>
#include <mbedtls/md.h> // For HMAC-SHA1
#include <mbedtls/sha1.h> // If needed directly (HMAC usually wraps it)
#include <esp_log.h>
#include <TimeLib.h> // For time_t manipulation if needed, but NTPClient might suffice

static const char* TAG = "TOTP";

// NTP Client setup
WiFiUDP ntpUDP;
// Use pool.ntp.org or a specific regional server
NTPClient timeClient(ntpUDP, "pool.ntp.org", 0, 60000); // Offset 0, update interval 60s

// State
static bool time_synced = false;
static uint8_t shared_secret[64]; // Buffer for the secret (max SHA512 block size, adjust if needed)
static size_t secret_length = 0;

// Function to convert seconds since epoch to big-endian 8-byte array
static void time_to_bytes(time_t t, uint8_t* buffer) {
    uint64_t time_counter = t / TOTP_TIME_STEP;
    // ESP32 is little-endian, need big-endian for TOTP standard
    buffer[0] = (time_counter >> 56) & 0xFF;
    buffer[1] = (time_counter >> 48) & 0xFF;
    buffer[2] = (time_counter >> 40) & 0xFF;
    buffer[3] = (time_counter >> 32) & 0xFF;
    buffer[4] = (time_counter >> 24) & 0xFF;
    buffer[5] = (time_counter >> 16) & 0xFF;
    buffer[6] = (time_counter >> 8) & 0xFF;
    buffer[7] = (time_counter >> 0) & 0xFF;
}

// Generates TOTP code for a given time value (mainly for testing/verification)
static uint32_t generateCode(time_t t) {
    if (secret_length == 0) {
        ESP_LOGE(TAG, "TOTP secret key not loaded.");
        return 0; // Indicate error
    }

    uint8_t time_bytes[8];
    time_to_bytes(t, time_bytes);

    uint8_t hash[MBEDTLS_MD_MAX_SIZE]; // Max size for HMAC output
    size_t hash_len = 20; // SHA1 hash length is 20 bytes

    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
    if (!md_info) {
        ESP_LOGE(TAG, "Failed to get SHA1 md info");
        return 0;
    }

    int ret = mbedtls_md_hmac(md_info, shared_secret, secret_length, time_bytes, sizeof(time_bytes), hash);
    if (ret != 0) {
        ESP_LOGE(TAG, "HMAC-SHA1 calculation failed: %d", ret);
        return 0;
    }

    // Dynamic Truncation (RFC 4226 Section 5.3)
    int offset = hash[hash_len - 1] & 0x0f;
    uint32_t binary_code =
        ((hash[offset] & 0x7f) << 24) |
        ((hash[offset + 1] & 0xff) << 16) |
        ((hash[offset + 2] & 0xff) << 8) |
        (hash[offset + 3] & 0xff);

    // Typically 6 digits
    uint32_t totp_code = binary_code % 1000000;

    // Clean up potentially sensitive hash data
    memset(hash, 0, sizeof(hash));

    return totp_code;
}

bool totp_init() {
    ESP_LOGI(TAG, "Initializing TOTP module...");
    // Attempt to load the secret from ATECC608A
    // Assuming readSecretFromSlot handles buffer size check
    if (!readSecretFromSlot(ATECC608A_TOTP_SECRET_SLOT, shared_secret, sizeof(shared_secret))) {
        ESP_LOGE(TAG, "Failed to read TOTP secret from ATECC608A Slot %d!", ATECC608A_TOTP_SECRET_SLOT);
        secret_length = 0; // Ensure length is 0 on failure
        return false;
    }
    // Determine actual secret length (ATECC608A slots are fixed size, often 32 or 36 bytes)
    // Need a mechanism to know the *actual* length used for the key (e.g., store length alongside, or assume fixed)
    // For HMAC-SHA1, keys longer than block size (64 bytes) are hashed down, but it's usually best practice
    // to use keys <= block size. Assuming the slot holds exactly the key needed, e.g. 20 bytes.
    // ** Placeholder: Assume key is 20 bytes for demonstration **
    secret_length = 20; // !!! Adjust this based on actual provisioning !!!
    ESP_LOGI(TAG, "TOTP Secret loaded from ATECC608A (assuming length %d bytes)", secret_length);


    timeClient.begin();
    ESP_LOGI(TAG, "NTP Client started.");
    // Attempt initial time sync
    syncNTPTime();
    return secret_length > 0; // Init successful if secret loaded
}

bool syncNTPTime() {
    ESP_LOGI(TAG, "Attempting NTP time synchronization...");
    if (WiFi.status() != WL_CONNECTED) {
        ESP_LOGW(TAG, "WiFi not connected. Cannot sync NTP.");
        time_synced = false;
        return false;
    }

    if (timeClient.forceUpdate()) {
        time_synced = true;
        setTime(timeClient.getEpochTime()); // Optional: Sync system time using TimeLib if used elsewhere
        ESP_LOGI(TAG, "NTP time synchronized successfully: %s", timeClient.getFormattedTime().c_str());
        return true;
    } else {
        time_synced = false;
        ESP_LOGE(TAG, "NTP time synchronization failed.");
        return false;
    }
}

time_t getCurrentTime() {
    if (!time_synced) {
       // Attempt a quick update if not synced, but don't block excessively
       if (WiFi.status() == WL_CONNECTED) {
           timeClient.update();
       }
       // Return 0 or epoch time if still not synced after quick check
       if (!timeClient.isTimeSet()) {
            ESP_LOGW(TAG, "Time not synchronized.");
            return 0; // Indicate error or invalid time
       }
    }
    return timeClient.getEpochTime();
}

bool isTimeSynced() {
    // Check NTPClient's internal status or our flag
    time_synced = timeClient.isTimeSet();
    return time_synced;
}

bool verifyTOTP(uint32_t userCode) {
    if (!isTimeSynced()) {
        ESP_LOGE(TAG, "Cannot verify TOTP: Time not synchronized.");
        // Optional: Try a forced sync here? Could introduce delays.
        // syncNTPTime();
        // if (!isTimeSynced()) return false; // Still failed
        return false; // Fail closed if time is uncertain
    }
     if (secret_length == 0) {
        ESP_LOGE(TAG, "Cannot verify TOTP: Secret key not loaded.");
        return false;
    }

    time_t current_time = getCurrentTime();
    ESP_LOGD(TAG, "Verifying TOTP code %u against time %lu", userCode, current_time);

    // Check current, previous, and next time steps within the allowed window
    for (int i = -TOTP_WINDOW; i <= TOTP_WINDOW; ++i) {
        time_t check_time = current_time + (i * TOTP_TIME_STEP);
        uint32_t serverCode = generateCode(check_time);
        ESP_LOGD(TAG, "Checking window %d (time %lu): Generated code %u", i, check_time, serverCode);
        if (serverCode != 0 && serverCode == userCode) {
            ESP_LOGI(TAG, "TOTP code %u verified successfully for time window %d.", userCode, i);
            return true;
        }
    }

    ESP_LOGW(TAG, "TOTP code %u verification failed.", userCode);
    return false;
}