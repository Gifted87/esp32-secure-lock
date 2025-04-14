#ifndef COMMS_H
#define COMMS_H

#include <Arduino.h>

namespace Comms {

    enum class Status {
        DISCONNECTED,
        CONNECTING,
        CONNECTED,
        CONNECTION_FAILED,
        MQTT_ERROR
    };

    // Callback types for received messages
    // Parameter: decrypted payload, payload length
    typedef void (*CommandCallback)(const uint8_t*, size_t);

    bool init(CommandCallback cmdCallback); // Pass callback for command processing
    void connect();
    bool loop(); // Needs to be called regularly to maintain connection & check messages
    Status getStatus();

    // Publish status securely (encrypts payload)
    bool publishStatus(const char* subtopic, const char* message);
    // Publish raw data (e.g., heartbeat, assumes no encryption needed or handled externally)
    bool publishRaw(const char* topic, const char* payload, bool retained = false);

    // --- Secure Communication Specifics ---
    // Expose functions needed by other modules if necessary
    // (e.g., if main needs to trigger a signature verification on non-MQTT data)
    // bool verifyExternalDataSignature(const uint8_t* data, size_t data_len, const uint8_t* signature);
    // bool signDataForExternal(const uint8_t* data, size_t data_len, uint8_t* signature_buffer);

} // namespace Comms

#endif // COMMS_H