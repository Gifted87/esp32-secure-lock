#include "security_utils.h"
#include "../config.h" // Include config for AES key (placeholder)
#include <mbedtls/aes.h>
#include <hwcrypto/aes.h> // ESP32 hardware AES
#include <esp_log.h>
#include <esp_random.h> // For IV generation
#include <string.h>     // For memcpy, memset

static const char* TAG = "AES_Engine";

// PKCS#7 Padding functions
static size_t pkcs7_padded_length(size_t data_len) {
    return data_len + (16 - (data_len % 16));
}

static void pkcs7_pad(uint8_t* buffer, size_t data_len, size_t padded_len) {
    uint8_t padding_value = padded_len - data_len;
    for (size_t i = data_len; i < padded_len; ++i) {
        buffer[i] = padding_value;
    }
}

static bool pkcs7_unpad(const uint8_t* buffer, size_t padded_len, size_t& data_len) {
    if (padded_len == 0 || padded_len % 16 != 0) {
        ESP_LOGE(TAG, "Invalid padded length: %d", padded_len);
        return false;
    }
    uint8_t padding_value = buffer[padded_len - 1];
    if (padding_value == 0 || padding_value > 16) {
        ESP_LOGE(TAG, "Invalid padding value: %d", padding_value);
        return false; // Invalid padding value
    }
    for (size_t i = padded_len - padding_value; i < padded_len - 1; ++i) {
        if (buffer[i] != padding_value) {
            ESP_LOGE(TAG, "Padding mismatch at index %d", i);
            return false; // Padding is corrupted
        }
    }
    data_len = padded_len - padding_value;
    return true;
}


bool aes_engine_init() {
    // Potential pre-computation or hardware checks if needed
    ESP_LOGI(TAG, "Hardware AES Engine Initialized (using mbedTLS HAL)");
    return true;
}

// Encrypts plaintext using AES-256-CBC with hardware acceleration, PKCS7 padding, and random IV.
// Output format: [16 byte IV][Encrypted Data with Padding]
bool encryptPacket(const uint8_t* plaintext, size_t plaintext_len,
                   const uint8_t* key, size_t key_len_bits,
                   uint8_t* output_buffer, size_t output_buffer_len, size_t& encrypted_len)
{
    if (key_len_bits != 256) {
        ESP_LOGE(TAG, "Only AES-256 is supported.");
        return false;
    }
    if (!plaintext || plaintext_len == 0 || !key || !output_buffer) {
        ESP_LOGE(TAG, "Invalid arguments for encryption.");
        return false;
    }

    // 1. Calculate padded length and required output buffer size
    size_t padded_data_len = pkcs7_padded_length(plaintext_len);
    size_t required_output_len = 16 + padded_data_len; // 16 bytes for IV + padded data

    if (output_buffer_len < required_output_len) {
        ESP_LOGE(TAG, "Output buffer too small. Need %d, have %d", required_output_len, output_buffer_len);
        return false;
    }

    // 2. Generate random IV
    uint8_t iv[16];
    esp_fill_random(iv, sizeof(iv));
    memcpy(output_buffer, iv, 16); // Copy IV to the beginning of the output buffer

    // 3. Prepare padded plaintext
    // Create a temporary buffer for padded data to avoid modifying original plaintext buffer if it's const
    uint8_t* padded_plaintext = (uint8_t*)malloc(padded_data_len);
    if (!padded_plaintext) {
         ESP_LOGE(TAG, "Failed to allocate memory for padding");
         return false;
    }
    memcpy(padded_plaintext, plaintext, plaintext_len);
    pkcs7_pad(padded_plaintext, plaintext_len, padded_data_len);

    // 4. Initialize AES context and set key
    esp_aes_context ctx;
    esp_aes_init(&ctx);
    int ret = esp_aes_setkey(&ctx, key, key_len_bits);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to set AES key: %d", ret);
        esp_aes_free(&ctx); // Ensure context is freed
        free(padded_plaintext);
        return false;
    }

    // 5. Perform encryption (Hardware accelerated CBC)
    // Note: esp_aes_crypt_cbc encrypts in-place, so output is written to `output_buffer + 16`
    memcpy(output_buffer + 16, padded_plaintext, padded_data_len); // Copy padded data to output buffer after IV
    ret = esp_aes_crypt_cbc(&ctx, ESP_AES_ENCRYPT, padded_data_len, iv, output_buffer + 16, output_buffer + 16);
    if (ret != 0) {
        ESP_LOGE(TAG, "AES encryption failed: %d", ret);
        esp_aes_free(&ctx);
        free(padded_plaintext);
        // Security: Overwrite potentially sensitive data in output buffer on failure
        memset(output_buffer, 0, required_output_len);
        return false;
    }

    // 6. Clean up
    esp_aes_free(&ctx); // Zeroizes key in hardware context
    free(padded_plaintext); // Free temporary padded buffer
    encrypted_len = required_output_len;
    ESP_LOGD(TAG, "Encryption successful. Plaintext len: %d, Padded len: %d, Output len (IV+Cipher): %d", plaintext_len, padded_data_len, encrypted_len);

    return true;
}

// Decrypts ciphertext (IV prepended) using AES-256-CBC with hardware acceleration and removes PKCS7 padding.
// Input format: [16 byte IV][Encrypted Data with Padding]
bool decryptPacket(const uint8_t* ciphertext_with_iv, size_t ciphertext_len,
                   const uint8_t* key, size_t key_len_bits,
                   uint8_t* output_buffer, size_t output_buffer_len, size_t& decrypted_len)
{
    if (key_len_bits != 256) {
        ESP_LOGE(TAG, "Only AES-256 is supported.");
        return false;
    }
     if (!ciphertext_with_iv || ciphertext_len < 16 + 16 /* IV + min 1 block */ || ciphertext_len % 16 != 0 || !key || !output_buffer) {
        ESP_LOGE(TAG, "Invalid arguments for decryption or invalid ciphertext length %d.", ciphertext_len);
        return false;
    }

    // 1. Extract IV and actual ciphertext length
    const uint8_t* iv = ciphertext_with_iv;
    const uint8_t* ciphertext = ciphertext_with_iv + 16;
    size_t actual_ciphertext_len = ciphertext_len - 16;

    if (output_buffer_len < actual_ciphertext_len) {
         ESP_LOGE(TAG, "Output buffer too small for decrypted data. Need %d, have %d", actual_ciphertext_len, output_buffer_len);
        return false;
    }

    // 2. Initialize AES context and set key
    esp_aes_context ctx;
    esp_aes_init(&ctx);
    int ret = esp_aes_setkey(&ctx, key, key_len_bits);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to set AES key: %d", ret);
        esp_aes_free(&ctx);
        return false;
    }

    // 3. Perform decryption (Hardware accelerated CBC)
    // Decrypt in-place into the output buffer
    memcpy(output_buffer, ciphertext, actual_ciphertext_len);
    // Need a mutable copy of the IV because mbedtls_aes_crypt_cbc might modify it (though ESP HAL might not)
    uint8_t iv_copy[16];
    memcpy(iv_copy, iv, 16);
    ret = esp_aes_crypt_cbc(&ctx, ESP_AES_DECRYPT, actual_ciphertext_len, iv_copy, output_buffer, output_buffer);
    if (ret != 0) {
        ESP_LOGE(TAG, "AES decryption failed: %d", ret);
        esp_aes_free(&ctx);
        // Security: Overwrite potentially sensitive data in output buffer on failure
        memset(output_buffer, 0, actual_ciphertext_len);
        return false;
    }

    // 4. Clean up AES context
    esp_aes_free(&ctx); // Zeroizes key in hardware context

    // 5. Remove PKCS#7 padding
    if (!pkcs7_unpad(output_buffer, actual_ciphertext_len, decrypted_len)) {
        ESP_LOGE(TAG, "Failed to unpad decrypted data. Possible padding oracle attack vector or corrupted data.");
        // Security: Overwrite potentially sensitive data in output buffer on failure
        memset(output_buffer, 0, actual_ciphertext_len);
        return false;
    }

    ESP_LOGD(TAG, "Decryption successful. Ciphertext len (IV+Cipher): %d, Padded len: %d, Decrypted len: %d", ciphertext_len, actual_ciphertext_len, decrypted_len);
    return true;
}