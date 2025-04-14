#ifndef SECURITY_UTILS_H
#define SECURITY_UTILS_H

#include <Arduino.h>
#include <stddef.h> // for size_t

// Forward declarations or includes for dependent types if necessary
// e.g., #include <mbedtls/pk.h> if passing context types

// -- AES Engine --
bool aes_engine_init(); // Optional: if specific init needed beyond context creation
bool encryptPacket(const uint8_t* plaintext, size_t plaintext_len,
                   const uint8_t* key, size_t key_len_bits,
                   uint8_t* output_buffer, size_t output_buffer_len, size_t& encrypted_len);
bool decryptPacket(const uint8_t* ciphertext_with_iv, size_t ciphertext_len,
                   const uint8_t* key, size_t key_len_bits,
                   uint8_t* output_buffer, size_t output_buffer_len, size_t& decrypted_len);

// -- TOTP --
bool totp_init();
bool syncNTPTime();
time_t getCurrentTime();
bool isTimeSynced();
bool verifyTOTP(uint32_t userCode);
// Note: TOTP generation typically happens server-side, but might be needed for testing
// uint32_t generateTOTP();

// -- ECDSA (using ATECC608A) --
bool ecdsa_init();
// Verifies data against a signature using the server's public key stored in ATECC608A
bool verifySignature(const uint8_t* data, size_t data_len,
                     const uint8_t* signature, size_t signature_len);
// Signs data using the device's private key stored in ATECC608A
bool signData(const uint8_t* data, size_t data_len,
              uint8_t* signature_buffer, size_t& signature_len);

// -- Secure Element (ATECC608A) Helpers --
bool secure_element_init();
bool readPublicKeyFromSlot(uint8_t slot_id, uint8_t* public_key_buffer); // Buffer should be 64 bytes for P256
bool readSecretFromSlot(uint8_t slot_id, uint8_t* secret_buffer, size_t buffer_len);
bool readCertDataFromSlot(uint8_t slot_id, uint8_t* cert_data_buffer, size_t& data_len); // Complex, may need chunking

// -- Secure Storage (Optional - Wrapper for NVS or ATECC608A User Zones) --
// bool secure_storage_write(const char* key, const uint8_t* data, size_t len);
// bool secure_storage_read(const char* key, uint8_t* data_buffer, size_t& len);

#endif // SECURITY_UTILS_H