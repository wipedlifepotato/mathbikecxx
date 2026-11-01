/*
 * Persistent settings.  The file is created next to the binary on first run
 * and contains the user's private destination, nickname, SAM settings, DH
 * sizes and relay-server options.
 */
#pragma once

#include <cstdint>
#include <string>

namespace TriMessage
{

struct Config
{
    std::string path;

    std::string nick;
    std::string privateKey;

    std::string samHost = "127.0.0.1";
    std::uint16_t samPort = 7656;
    std::string samSession;
    std::string samSignatureType = "DSA_SHA1";

    unsigned dhBits = 1024;
    unsigned groupBits = 128;
    unsigned secretBits = 256;
    unsigned rekeySecretBits = 128;
    unsigned maxPeerDhBits = 8192;
    bool allowHugeDh = false;

    bool serverMode = false;
    bool daemonMode = false;
    unsigned relayVersion = 2;
    unsigned relayLimit = 64;
    bool relayAnonymous = false;
    bool relayAskPlain = true;
    std::string relayPassword;
};

enum class LoadResult
{
    Ok,
    Missing,
    Error
};

Config defaultConfig();
std::string defaultConfigPath(const char* argv0);

LoadResult loadConfig(const std::string& path, Config& cfg, std::string& err);
bool saveConfig(const Config& cfg, std::string& err);

} // namespace TriMessage
