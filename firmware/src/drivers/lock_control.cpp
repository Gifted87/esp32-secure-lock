#include "drivers.h"
#include "../config.h" // For pin definitions
#include <esp_log.h>

static const char* TAG = "LockControl";

namespace LockControl {

    static State current_state = State::LOCKED; // Assume starts locked

    bool init() {
        pinMode(LOCK_PIN, OUTPUT);
        digitalWrite(LOCK_PIN, LOW); // Ensure lock is initially in the 'locked' state (assuming LOW=Locked)
        current_state = State::LOCKED;
        ESP_LOGI(TAG, "Lock control initialized on GPIO %d. Initial state: LOCKED.", LOCK_PIN);
        return true;
    }

    void unlock() {
        // Add check: Only unlock if currently locked?
        if (current_state == State::LOCKED) {
            ESP_LOGI(TAG, "Unlocking mechanism...");
            digitalWrite(LOCK_PIN, HIGH); // Assuming HIGH = Unlocked
            current_state = State::UNLOCKED;
            StatusIndicator::setPattern(StatusIndicator::Pattern::IDLE_UNLOCKED);
        } else {
            ESP_LOGD(TAG, "Already unlocked.");
        }
    }

    void lock() {
         // Add check: Only lock if currently unlocked?
         if (current_state == State::UNLOCKED) {
            ESP_LOGI(TAG, "Locking mechanism...");
            digitalWrite(LOCK_PIN, LOW); // Assuming LOW = Locked
            current_state = State::LOCKED;
            StatusIndicator::setPattern(StatusIndicator::Pattern::IDLE_LOCKED);
         } else {
              ESP_LOGD(TAG, "Already locked.");
         }
    }

    State getState() {
        return current_state;
    }

} // namespace LockControl