#include "drivers.h"
#include "../config.h" // For pin definitions
#include <MFRC522.h>
#include <SPI.h>
#include <esp_log.h>

static const char* TAG = "RFID_Driver";

// Use hardware SPI
MFRC522 mfrc522(RFID_SDA_PIN, RFID_RST_PIN); // SS/SDA pin, RST pin

// --- Anti-Cloning / Secure Key Placeholder ---
// This requires keys securely stored (e.g., ATECC608A) and a protocol.
// Example: Use a diversified key based on card UID and a master key from ATECC.
/*
#include "../security/security_utils.h" // Need ATECC access

bool RFID::authenticateAndReadSecure(MFRC522::Uid& uid, uint8_t blockAddr, uint8_t* rfid_key) {
    if (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial()) {
        return false; // No card or failed read
    }
    uid = mfrc522.uid;

    // ** NOVELTY / SECURITY: Diversified Key Generation (Conceptual) **
    // 1. Read master RFID key from ATECC608A_RFID_KEY_SLOT
    // uint8_t masterKey[16]; // AES key size
    // if (!readSecretFromSlot(ATECC608A_RFID_KEY_SLOT, masterKey, sizeof(masterKey))) { return false; }
    // 2. Derive diversified key using AES/CMAC using masterKey and uid.bytes
    // uint8_t diversifiedKey[6]; // MIFARE classic key size
    // derive_mifare_key(masterKey, uid.bytes, uid.size, diversifiedKey); // Implement this securely
    // 3. Prepare MIFARE Key structure
    // MFRC522::MIFARE_Key key;
    // memcpy(key.keyByte, diversifiedKey, 6);

    // Prepare MIFARE Key structure (using provided key for now)
    MFRC522::MIFARE_Key key;
    memcpy(key.keyByte, rfid_key, 6); // Use the passed key directly

    // Try to authenticate
    MFRC522::StatusCode status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, blockAddr, &key, &uid);
    if (status != MFRC522::STATUS_OK) {
        ESP_LOGW(TAG, "MIFARE Authentication Failed, block %d: %s", blockAddr, mfrc522.GetStatusCodeName(status));
        mfrc522.PICC_HaltA();      // Halt PICC
        mfrc522.PCD_StopCrypto1(); // Stop encryption on PCD
        return false;
    }

    // Authentication successful - Proceed to read/write data...
    ESP_LOGI(TAG, "MIFARE Authentication Success, block %d", blockAddr);

    // Example: Read block
    byte buffer[18];
    byte size = sizeof(buffer);
    status = mfrc522.MIFARE_Read(blockAddr, buffer, &size);
     if (status != MFRC522::STATUS_OK) {
        ESP_LOGE(TAG,"MIFARE Read Failed: %s", mfrc522.GetStatusCodeName(status));
        mfrc522.PICC_HaltA();
        mfrc522.PCD_StopCrypto1();
        return false;
     }
     ESP_LOGI(TAG,"Read block %d data: [DATA]", blockAddr); // Print buffer content securely

    // Remember to halt and stop crypto
    // mfrc522.PICC_HaltA();
    // mfrc522.PCD_StopCrypto1();
    return true;
}
*/


namespace RFID {

    bool init() {
        SPI.begin(RFID_SCK_PIN, RFID_MISO_PIN, RFID_SDA_PIN); // SCLK, MISO, MOSI
        mfrc522.PCD_Init(); // Init MFRC522 board
        delay(4); // Small delay recommended after init
        mfrc522.PCD_DumpVersionToSerial(); // Print version details for debugging
        ESP_LOGI(TAG, "MFRC522 Initialized on SPI.");
        // Perform self-test
        if (!mfrc522.PCD_PerformSelfTest()) {
            ESP_LOGE(TAG, "MFRC522 Self Test Failed!");
            return false;
        }
        mfrc522.PCD_AntennaOn(); // Turn antenna on
        ESP_LOGI(TAG, "MFRC522 Self Test OK, Antenna ON.");
        return true;
    }

    // Basic check and UID read - vulnerable to cloning if only UID is used.
    Status checkAndReadCard(MFRC522::Uid& uid) {
        // Look for new cards
        if (!mfrc522.PICC_IsNewCardPresent()) {
            return Status::NO_CARD;
        }

        // Select one of the cards
        if (!mfrc522.PICC_ReadCardSerial()) {
             ESP_LOGD(TAG, "Failed to read card serial.");
             // Don't halt yet, maybe retry? Or return READ_FAIL.
            return Status::CARD_PRESENT; // Card detected but couldn't read UID yet
        }

        // Store UID
        uid = mfrc522.uid;

        // Dump UID
        // ESP_LOGI(TAG, "Card UID:");
        // for (byte i = 0; i < mfrc522.uid.size; i++) {
        //     Serial.print(mfrc522.uid.uidByte[i] < 0x10 ? " 0" : " ");
        //     Serial.print(mfrc522.uid.uidByte[i], HEX);
        // }
        // Serial.println();

        return Status::READ_OK;
    }

    void halt() {
         mfrc522.PICC_HaltA();      // Halt PICC
         mfrc522.PCD_StopCrypto1(); // Stop encryption on PCD (important after auth)
    }

} // namespace RFID