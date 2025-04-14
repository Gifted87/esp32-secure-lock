#include "security_utils.h"
#include "../config.h"
#include <Arduino.h>
#include <Wire.h> // Needed for I2C communication with ATECC608A
#include <cryptoauthlib.h> // Main library header
#include <mbedtls/sha256.h>
#include <esp_log.h>
#include <string.h> // For memset

static const char* TAG = "ECDSA_ATECC";

// Global ATECC608A device configuration structure
ATCAIfaceCfg cfg_atecc608a_i2c = {
    .iface_type             = ATCA_I2C_IFACE,
    .devtype                = ATECC608A, // Specify the device type
    .atcai2c.slave_address  = ATECC608A_I2C_ADDRESS,
    .atcai2c.bus            = 1, // ESP32 typically uses I2C bus 1 (check your board)
    .atcai2c.baud           = 400000, // Can be 100000 or 400000
    .wake_delay             = 1500, // Delay in microseconds
    .rx_retries             = 20
};

static bool atecc_initialized = false;

// -- Secure Element Initialization --
bool secure_element_init() {
    if (atecc_initialized) {
        return true;
    }

    ESP_LOGI(TAG, "Initializing ATECC608A Secure Element via I2C...");

    // Initialize the HAL (Hardware Abstraction Layer for I2C)
    // Note: CryptoAuthLib's HAL might need specific pin configuration
    // if not using default ESP32 I2C pins. Wire.begin() might be needed beforehand.
    Wire.begin(); // Initialize default I2C pins

    ATCA_STATUS status = atcab_init(&cfg_atecc608a_i2c);

    if (status != ATCA_SUCCESS) {
        ESP_LOGE(TAG, "ATECC608A Initialization Failed! Status: 0x%02X", status);
        // Common issues: Incorrect I2C address, wiring problems, device not powered.
        return false;
    }

    // Optional: Read serial number to confirm communication
    uint8_t serial_number[ATCA_SERIAL_NUM_SIZE];
    status = atcab_read_serial_number(serial_number);
    if (status != ATCA_SUCCESS) {
         ESP_LOGE(TAG, "Failed to read ATECC608A Serial Number! Status: 0x%02X", status);
         atcab_release(); // Release context on failure
         return false;
    } else {
         ESP_LOGI(TAG, "ATECC608A Initialized Successfully. Serial: %02X%02X%02X%02X%02X%02X%02X%02X%02X",
            serial_number[0], serial_number[1], serial_number[2], serial_number[3],
            serial_number[4], serial_number[5], serial_number[6], serial_number[7], serial_number[8]);
    }

    atecc_initialized = true;
    return true;
}

// Helper function to read secrets (like TOTP key, RFID key)
bool readSecretFromSlot(uint8_t slot_id, uint8_t* secret_buffer, size_t buffer_len) {
     if (!atecc_initialized) {
        ESP_LOGE(TAG, "ATECC608A not initialized.");
        return false;
    }
    if (buffer_len < 32) {
        // ATECC608A slots are typically 32 bytes minimum for keys
        ESP_LOGE(TAG, "Buffer too small for slot read (%d bytes)", buffer_len);
        return false;
    }

    // Use atcab_read_zone for data/key slots. Size is typically fixed per slot config.
    // Assume reading a 32-byte block (standard key slot size)
    ATCA_STATUS status = atcab_read_zone(ATCA_ZONE_DATA, slot_id, 0, 0, secret_buffer, 32);

    if (status != ATCA_SUCCESS) {
        ESP_LOGE(TAG, "Failed to read secret from ATECC608A slot %d. Status: 0x%02X", slot_id, status);
        memset(secret_buffer, 0, buffer_len); // Clear buffer on failure
        return false;
    }
    ESP_LOGI(TAG, "Secret read successfully from slot %d", slot_id);
    return true;
}

// Helper to read a public key (P256 = 64 bytes)
bool readPublicKeyFromSlot(uint8_t slot_id, uint8_t* public_key_buffer) {
    if (!atecc_initialized) {
        ESP_LOGE(TAG, "ATECC608A not initialized.");
        return false;
    }
     // Public keys are read using atcab_read_pubkey
    ATCA_STATUS status = atcab_read_pubkey(slot_id, public_key_buffer);
    if (status != ATCA_SUCCESS) {
        ESP_LOGE(TAG, "Failed to read public key from ATECC608A slot %d. Status: 0x%02X", slot_id, status);
        memset(public_key_buffer, 0, 64); // Clear buffer on failure
        return false;
    }
     ESP_LOGI(TAG, "Public key read successfully from slot %d", slot_id);
    return true;
}

// Helper for certificate data (more complex, requires reading config zone first to get size)
// Simplified version: Assumes cert is stored in fixed-size blocks (e.g. 72 bytes)
bool readCertDataFromSlot(uint8_t slot_id, uint8_t* cert_data_buffer, size_t& data_len) {
     if (!atecc_initialized) {
        ESP_LOGE(TAG, "ATECC608A not initialized.");
        return false;
    }
    // Reading certificates requires knowing the size configured for the slot.
    // This is stored in the configuration zone. Reading requires multiple steps.
    // For simplicity, let's assume we read a fixed amount based on expected cert size.
    // Or, store the cert in the filesystem if it's large and only store the key in ATECC.
    ESP_LOGW(TAG, "Reading full certificate data from ATECC608A is complex. Implement based on specific provisioning and size knowledge.");
    // Example: Read first 72 bytes (common block size)
    size_t bytes_to_read = 72;
    if (data_len < bytes_to_read) {
         ESP_LOGE(TAG,"Buffer too small for cert read");
         return false;
    }
    ATCA_STATUS status = atcab_read_zone(ATCA_ZONE_DATA, slot_id, 0, 0, cert_data_buffer, bytes_to_read);
     if (status != ATCA_SUCCESS) {
        ESP_LOGE(TAG, "Failed partial cert read slot %d: 0x%02X", slot_id, status);
        memset(cert_data_buffer, 0, data_len);
        data_len = 0;
        return false;
     }
     data_len = bytes_to_read; // Return actual bytes read
     ESP_LOGI(TAG,"Partial cert data read (%d bytes) from slot %d", data_len, slot_id);
     return true;

    // A proper implementation would read the config zone to get the actual cert element size,
    // then read in chunks if necessary.
}


// -- ECDSA Initialization --
bool ecdsa_init() {
    // Relies on secure_element_init being called first
    if (!atecc_initialized) {
        ESP_LOGI(TAG, "Initializing ECDSA requires secure element...");
        if (!secure_element_init()) {
            return false;
        }
    }
    ESP_LOGI(TAG, "ECDSA module ready (using ATECC608A).");
    return true;
}

// Verifies data against a signature using the server's public key stored in ATECC608A
bool verifySignature(const uint8_t* data, size_t data_len,
                     const uint8_t* signature, size_t signature_len)
{
    if (!atecc_initialized) {
        ESP_LOGE(TAG, "ATECC608A not initialized. Cannot verify signature.");
        return false;
    }
    if (!data || data_len == 0 || !signature || signature_len != 64) { // P256 signatures are 64 bytes
        ESP_LOGE(TAG, "Invalid arguments for signature verification.");
        return false;
    }

    // 1. Calculate SHA-256 hash of the data
    uint8_t hash[32];
    mbedtls_sha256_context sha_ctx;
    mbedtls_sha256_init(&sha_ctx);
    // Use hardware acceleration if available via mbedtls config, otherwise software
    if (mbedtls_sha256_starts_ret(&sha_ctx, 0) != 0) { // 0 for SHA-256
        ESP_LOGE(TAG, "SHA256 context start failed");
        mbedtls_sha256_free(&sha_ctx);
        return false;
    }
    if (mbedtls_sha256_update_ret(&sha_ctx, data, data_len) != 0) {
         ESP_LOGE(TAG, "SHA256 update failed");
         mbedtls_sha256_free(&sha_ctx);
        return false;
    }
     if (mbedtls_sha256_finish_ret(&sha_ctx, hash) != 0) {
         ESP_LOGE(TAG, "SHA256 finish failed");
         mbedtls_sha256_free(&sha_ctx);
        return false;
     }
    mbedtls_sha256_free(&sha_ctx);
    ESP_LOGD(TAG, "Calculated SHA256 hash of data.");

    // 2. Read the server's public key from the ATECC608A slot
    uint8_t server_public_key[64]; // P256 public key is 64 bytes (X, Y)
    if (!readPublicKeyFromSlot(ATECC608A_SERVER_PUBLIC_KEY_SLOT, server_public_key)) {
        ESP_LOGE(TAG, "Failed to read server public key from slot %d", ATECC608A_SERVER_PUBLIC_KEY_SLOT);
        return false;
    }

    // 3. Verify the signature using the hash and the public key with ATECC608A
    bool is_verified = false;
    ATCA_STATUS status = atcab_verify_extern(hash, signature, server_public_key, &is_verified);

    if (status != ATCA_SUCCESS) {
        ESP_LOGE(TAG, "ATECC608A verification command failed: 0x%02X", status);
        return false;
    }

    if (is_verified) {
        ESP_LOGI(TAG, "ECDSA Signature VALID");
    } else {
        ESP_LOGW(TAG, "ECDSA Signature INVALID!");
    }

    // Securely clear sensitive data from stack if needed (though hash/pubkey less critical than privkey)
    memset(hash, 0, sizeof(hash));
    memset(server_public_key, 0, sizeof(server_public_key));

    return is_verified;
}

// Signs data using the device's private key stored in ATECC608A
bool signData(const uint8_t* data, size_t data_len,
              uint8_t* signature_buffer, size_t& signature_len) // Buffer must be 64 bytes
{
     if (!atecc_initialized) {
        ESP_LOGE(TAG, "ATECC608A not initialized. Cannot sign data.");
        return false;
    }
    if (!data || data_len == 0 || !signature_buffer || signature_len < 64) {
        ESP_LOGE(TAG, "Invalid arguments for signing or buffer too small.");
        signature_len = 0;
        return false;
    }

    // 1. Calculate SHA-256 hash of the data
    uint8_t hash[32];
    mbedtls_sha256_context sha_ctx;
    mbedtls_sha256_init(&sha_ctx);
    if (mbedtls_sha256_starts_ret(&sha_ctx, 0) != 0 ||
        mbedtls_sha256_update_ret(&sha_ctx, data, data_len) != 0 ||
        mbedtls_sha256_finish_ret(&sha_ctx, hash) != 0) {
        ESP_LOGE(TAG, "SHA256 calculation failed during signing");
        mbedtls_sha256_free(&sha_ctx);
        signature_len = 0;
        return false;
    }
    mbedtls_sha256_free(&sha_ctx);
    ESP_LOGD(TAG, "Calculated SHA256 hash for signing.");

    // 2. Sign the hash using the private key in the specified ATECC608A slot
    ATCA_STATUS status = atcab_sign(ATECC608A_DEVICE_PRIVATE_KEY_SLOT, hash, signature_buffer);

    if (status != ATCA_SUCCESS) {
        ESP_LOGE(TAG, "ATECC608A signing command failed: 0x%02X", status);
        signature_len = 0;
        memset(signature_buffer, 0, 64); // Clear buffer on failure
        return false;
    }

    signature_len = 64; // ECDSA P256 signature is 64 bytes
    ESP_LOGI(TAG, "Data signed successfully using ATECC608A key slot %d.", ATECC608A_DEVICE_PRIVATE_KEY_SLOT);
    return true;
}


// --- ATECC608A mbedTLS Integration Hooks (Advanced - Placeholder) ---
// This section is complex and requires linking CryptoAuthLib's mbedTLS HAL/hooks
// during the build process. This allows mbedTLS (used by WiFiClientSecure)
// to use the ATECC608A for private key operations during the TLS handshake.

#ifdef ENABLE_ATECC_MBEDTLS_HOOKS // Define this flag if attempting integration

#include <mbedtls/pk.h>
#include <mbedtls/ecdsa.h>
#include <atca_mbedtls_pk.h> // Header providing the bridge functions

// Global context for the ATECC608A private key usable by mbedTLS
mbedtls_pk_context atecc_pk_ctx;

bool setup_atecc_mbedtls_key() {
    if (!atecc_initialized) {
        ESP_LOGE(TAG, "ATECC not init before setting up mbedtls key");
        return false;
    }
    ESP_LOGI(TAG, "Setting up mbedTLS PK context for ATECC608A slot %d", ATECC608A_DEVICE_PRIVATE_KEY_SLOT);
    // Initialize the mbedTLS PK context to use the ATECC608A key slot
    int ret = atca_mbedtls_pk_init(&atecc_pk_ctx, ATECC608A_DEVICE_PRIVATE_KEY_SLOT);
    if (ret != 0) {
        ESP_LOGE(TAG, "atca_mbedtls_pk_init failed: -0x%04X", -ret);
        return false;
    }
    ESP_LOGI(TAG, "mbedTLS PK context initialized successfully for ATECC.");
    return true;
}

// Function to get the configured mbedTLS key context (needed by mqtt_tls.cpp)
mbedtls_pk_context* get_atecc_mbedtls_key_ctx() {
    // Ensure setup_atecc_mbedtls_key() has been called successfully before this
    return &atecc_pk_ctx;
}

#endif // ENABLE_ATECC_MBEDTLS_HOOKS