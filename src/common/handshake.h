/*
 * HELLO / HELLO_ACK payloads.
 *
 * TRI-HS/2 adds two fields at the end:
 *   relayVersion: 0 = direct peer, 2 = encrypted relay, 3 = plaintext relay
 *   role:         "client", "server" or "relay"
 */
#pragma once

#include <cstdint>
#include <string>

namespace TriMessage
{

constexpr const char* kVersionString = "TRI-CHAT/3";
constexpr const char* kHandshakeVersion = "TRI-HS/3";

constexpr std::uint8_t kRelayDirect = 0;
constexpr std::uint8_t kRelayEncrypted = 2;
constexpr std::uint8_t kRelayPlain = 3;

struct HsData
{
    std::string nick;
    std::string dest;
    std::string fp;
    std::string p;
    std::string g;
    std::string dhPub;
    std::string challenge;
    std::uint8_t relayVersion = kRelayDirect;
    std::string role;
    bool passwordRequired = false;
};

std::string encodeHs(const HsData& h);
bool decodeHs(const std::string& b64, HsData& h);
std::string makeTranscript(const HsData& client, const HsData& server);

} // namespace TriMessage
