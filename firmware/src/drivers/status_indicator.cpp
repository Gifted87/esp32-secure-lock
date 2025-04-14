#include "drivers.h"
#include <Arduino.h>
#include <Ticker.h> // For blinking/pulsing

// --- Configuration ---
#define BLINK_FAST_MS 150
#define BLINK_SLOW_MS 750
#define PULSE_STEP 5
#define PULSE_DELAY_MS 10

namespace StatusIndicator {

    // Pin definitions (initialized in init)
    static int ledR = -1;
    static int ledG = -1;
    static int ledB = -1;
    static bool isRgb = false;

    // State for blinking/pulsing
    static Pattern currentPattern = Pattern::IDLE_LOCKED;
    static bool ledState = false; // For simple blinking
    static int pulseBrightness = 0;
    static bool pulseUp = true;
    static Ticker blinker;
    static Ticker pulser;

    // --- Internal Functions ---

    // Simple ON/OFF based on pattern (assumes single LED or uses primary color for RGB)
    void toggleSimpleLed() {
        ledState = !ledState;
        int pinToUse = -1;
        int onState = HIGH; // Default for simple LED

        // Determine which pin/color to blink based on pattern
        switch (currentPattern) {
             case Pattern::ERROR_NTP:
                pinToUse = (ledState ? ledR : ledB); // Alternate Red/Blue
                break;
             case Pattern::ERROR_MQTT:
                 pinToUse = (ledState ? ledR : ledG); // Alternate Red/Yellow (use Green if no Yellow)
                break;
             case Pattern::ERROR_GENERIC:
             case Pattern::ERROR_ATECC:
             case Pattern::IDLE_LOCKED: // Use Red
                pinToUse = ledR;
                break;
             case Pattern::AUTH_SUCCESS:
             case Pattern::IDLE_UNLOCKED: // Use Green
                 pinToUse = ledG;
                 break;
            case Pattern::SYSTEM_BOOTING:
            case Pattern::AUTH_WAITING: // Use Blue
                 pinToUse = ledB;
                 break;
            default: // Default to Red for unknown errors/states
                 pinToUse = ledR;
                 break;
        }

        if (pinToUse != -1) {
            // Turn off other LEDs if RGB
             if (isRgb) {
                if (pinToUse != ledR && ledR != -1) digitalWrite(ledR, LOW);
                if (pinToUse != ledG && ledG != -1) digitalWrite(ledG, LOW);
                if (pinToUse != ledB && ledB != -1) digitalWrite(ledB, LOW);
            }
             // Set the target LED state
            digitalWrite(pinToUse, ledState ? onState : !onState);
        }
    }

    void stepPulseLed() {
        if (pulseUp) {
            pulseBrightness += PULSE_STEP;
            if (pulseBrightness >= 255) {
                pulseBrightness = 255;
                pulseUp = false;
            }
        } else {
            pulseBrightness -= PULSE_STEP;
            if (pulseBrightness <= 0) {
                pulseBrightness = 0;
                pulseUp = true;
            }
        }

        int pinToUse = -1;
         switch (currentPattern) {
             case Pattern::AUTH_WAITING: pinToUse = ledB; break;
             case Pattern::CONFIG_MODE: pinToUse = ledG; break; // Use Green for Yellow pulse if no dedicated Yellow
             default: pinToUse = -1; break; // Should not pulse other states
         }

        if (pinToUse != -1) {
            // Assuming common cathode RGB LED where PWM drives pins LOW
            // If common anode or simple LED, logic needs inversion/adjustment.
            // Use analogWrite for PWM control if available/configured
            #ifdef ESP32 // ESP32 has ledc for PWM
                ledcWrite(0, 255 - pulseBrightness); // Assuming PWM channel 0 attached to pinToUse
            #else // Basic Arduino analogWrite
                analogWrite(pinToUse, 255 - pulseBrightness);
            #endif
        }
    }


    void setSolidColor(int r, int g, int b) {
        // Detach tickers first
        blinker.detach();
        pulser.detach();

        #ifdef ESP32
            // Ensure PWM channels are detached if previously used
            ledcDetachPin(ledR); ledcDetachPin(ledG); ledcDetachPin(ledB);
        #endif

        if (ledR != -1) digitalWrite(ledR, r ? HIGH : LOW);
        if (ledG != -1) digitalWrite(ledG, g ? HIGH : LOW);
        if (ledB != -1) digitalWrite(ledB, b ? HIGH : LOW);
    }


    // --- Public API ---

    bool init(int ledPinRed, int ledPinGreen, int ledPinBlue) {
        ledR = ledPinRed;
        ledG = ledPinGreen;
        ledB = ledPinBlue;

        int count = 0;
        if (ledR != -1) { pinMode(ledR, OUTPUT); digitalWrite(ledR, LOW); count++; }
        if (ledG != -1) { pinMode(ledG, OUTPUT); digitalWrite(ledG, LOW); count++; }
        if (ledB != -1) { pinMode(ledB, OUTPUT); digitalWrite(ledB, LOW); count++; }

        isRgb = (count >= 2); // Consider it RGB if at least 2 pins are defined

        #ifdef ESP32 // Setup PWM channels if using ESP32 for pulsing/fading
            if (isRgb || ledPinBlue != -1 || ledPinGreen != -1) { // If using colors needing PWM
                // Setup PWM channel 0 (example) - choose freq/resolution appropriately
                ledcSetup(0, 5000, 8); // Channel 0, 5kHz, 8-bit resolution
                // Attach pins later when needed in stepPulseLed or setSolidColor with PWM
            }
        #endif

        setPattern(Pattern::SYSTEM_BOOTING); // Initial state
        return (count > 0); // Return true if at least one LED pin was configured
    }

    void setPattern(Pattern pattern) {
        currentPattern = pattern;
        ledState = false; // Reset blink state
        pulseBrightness = 0; // Reset pulse state
        pulseUp = true;

        // Detach previous tickers
        blinker.detach();
        pulser.detach();

        #ifdef ESP32 // Detach pins from PWM channels when changing pattern
           if (ledR != -1) ledcDetachPin(ledR);
           if (ledG != -1) ledcDetachPin(ledG);
           if (ledB != -1) ledcDetachPin(ledB);
        #endif


        switch (pattern) {
            // Solid Colors
            case Pattern::IDLE_LOCKED:    setSolidColor(1, 0, 0); break; // Red
            case Pattern::IDLE_UNLOCKED:  setSolidColor(0, 1, 0); break; // Green

            // Simple Blinking
            case Pattern::AUTH_SUCCESS:
                 setSolidColor(0, 1, 0); // Quick Green flash
                 blinker.once_ms(300, [](){ setPattern(LockControl::getState() == LockControl::State::LOCKED ? Pattern::IDLE_LOCKED : Pattern::IDLE_UNLOCKED); });
                 break;
            case Pattern::AUTH_FAIL:
                 setSolidColor(1, 0, 0); // Quick Red flash
                 blinker.once_ms(300, [](){ setPattern(LockControl::getState() == LockControl::State::LOCKED ? Pattern::IDLE_LOCKED : Pattern::IDLE_UNLOCKED); });
                 break;
            case Pattern::ERROR_GENERIC:
            case Pattern::ERROR_ATECC:
                blinker.attach_ms(BLINK_FAST_MS, toggleSimpleLed); break; // Fast Red blink
            case Pattern::SYSTEM_BOOTING:
                blinker.attach_ms(BLINK_SLOW_MS, toggleSimpleLed); break; // Slow Blue blink

            // Alternating Blinking
             case Pattern::ERROR_NTP: // Red / Blue
             case Pattern::ERROR_MQTT: // Red / Yellow (Green)
                 blinker.attach_ms(BLINK_SLOW_MS, toggleSimpleLed); break;


            // Pulsing
            case Pattern::AUTH_WAITING: // Pulse Blue
            case Pattern::CONFIG_MODE:  // Pulse Yellow (Green)
                 #ifdef ESP32 // Attach pin to PWM channel
                    int pinToPulse = (pattern == Pattern::AUTH_WAITING) ? ledB : ledG;
                    if (pinToPulse != -1) {
                        ledcAttachPin(pinToPulse, 0); // Attach pin to channel 0
                        pulser.attach_ms(PULSE_DELAY_MS, stepPulseLed);
                    } else { setSolidColor(0,0,1); } // Fallback to solid blue/green if no pin
                 #else // Fallback for non-ESP32 or if PWM not configured
                    setSolidColor(0, 0, (pattern == Pattern::AUTH_WAITING)); // Solid Blue or off
                 #endif
                break;

            default: setSolidColor(1, 0, 0); break; // Default to solid red on unknown
        }
        // Ensure initial state is set for blinking patterns
        if (pattern != Pattern::IDLE_LOCKED && pattern != Pattern::IDLE_UNLOCKED && pattern != Pattern::AUTH_SUCCESS && pattern != Pattern::AUTH_FAIL) {
             toggleSimpleLed(); // Set initial state for blinking/alternating
        }
    }

    void update() {
        // Ticker library usually handles callbacks automatically.
        // This function might be needed if using manual timing instead of Ticker.
        // For now, it's empty.
    }

} // namespace StatusIndicator