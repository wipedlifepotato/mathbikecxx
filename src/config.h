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

    /*
     * Password used to encrypt this file at rest.  It is never written into
     * the file itself and is not the relay chat password.
     */
    std::string configPassword;
    bool configEncrypted = false;

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
    bool sandboxEnabled = true;
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
    NeedsPassword,
    Error
};

Config defaultConfig();
std::string defaultConfigPath(const char* argv0);

/* Returns NeedsPassword when the file is encrypted and password is empty. */
LoadResult loadConfig(const std::string& path, const std::string& password,
                      Config& cfg, std::string& err);
bool saveConfig(Config& cfg, std::string& err);

/* True when the file starts with the encrypted-config marker. */
bool configIsEncrypted(const std::string& path);

} // namespace TriMessage
