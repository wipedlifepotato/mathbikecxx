#include "handshake.h"

#include "util.h"

namespace TriMessage
{

std::string encodeHs(const HsData& h)
{
    std::string s = kHandshakeVersion;
    s += "\n" + h.nick;
    s += "\n" + h.dest;
    s += "\n" + h.fp;
    s += "\n" + h.p;
    s += "\n" + h.g;
    s += "\n" + h.dhPub;
    s += "\n" + h.challenge;
    s += "\n" + std::to_string(h.relayVersion);
    s += "\n" + h.role;
    s += "\n" + std::string(h.passwordRequired ? "1" : "0");
    return base64Encode(s);
}

bool decodeHs(const std::string& b64, HsData& h)
{
    std::vector<std::uint8_t> raw;
    if (!base64Decode(b64, raw))
        return false;

    const std::string s(raw.begin(), raw.end());
    const auto f = splitChar(s, '\n');
    const bool oldFormat = (f.size() == 10 && f[0] == "TRI-HS/2");
    if ((!oldFormat && f.size() != 11) ||
        (!oldFormat && f[0] != kHandshakeVersion))
        return false;

    h.nick = f[1];
    h.dest = f[2];
    h.fp = f[3];
    h.p = f[4];
    h.g = f[5];
    h.dhPub = f[6];
    h.challenge = f[7];
    h.role = f[9];

    try
    {
        h.relayVersion = static_cast<std::uint8_t>(std::stoi(f[8]));
    }
    catch (...)
    {
        return false;
    }

    if (h.relayVersion != kRelayDirect &&
        h.relayVersion != kRelayEncrypted &&
        h.relayVersion != kRelayPlain)
        return false;

    if (!oldFormat)
        h.passwordRequired = (f[10] == "1");

    return !h.nick.empty() && !h.dest.empty();
}

std::string makeTranscript(const HsData& client, const HsData& server)
{
    return std::string(kVersionString) + "|" + client.nick + "|" + client.dest + "|" +
           client.challenge + "|" + server.nick + "|" + server.dest + "|" +
           server.challenge + "|" + std::to_string(client.relayVersion) + "|" +
           std::to_string(server.relayVersion) + "|" + client.role + "|" + server.role +
           "|" + (server.passwordRequired ? "pw" : "open");
}

} // namespace TriMessage
