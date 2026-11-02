#include "config.h"

#include "common/hash.h"
#include "common/platform.h"
#include "common/util.h"

#include "ChaCha20.h"

#include <array>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace TriMessage
{

namespace
{

constexpr const char* kEncryptedMagic = "TRIGANDE-ENCRYPTED-CONFIG-V1";
constexpr unsigned kKdfIterations = 210000;
constexpr std::size_t kSaltBytes = 16;
constexpr std::size_t kNonceBytes = 12;

bool parseBool(const std::string& value, bool& out)
{
    const std::string v = lower(trimCopy(value));
    if (v == "1" || v == "true" || v == "yes" || v == "on")
    {
        out = true;
        return true;
    }
    if (v == "0" || v == "false" || v == "no" || v == "off")
    {
        out = false;
        return true;
    }
    return false;
}

bool parseUInt(const std::string& value, unsigned& out, unsigned maxValue)
{
    try
    {
        const unsigned long v = std::stoul(trimCopy(value));
        if (v > maxValue)
            return false;
        out = static_cast<unsigned>(v);
        return true;
    }
    catch (...)
    {
        return false;
    }
}

std::string b2s(bool v)
{
    return v ? "true" : "false";
}

bool readWholeFile(const std::string& path, std::string& out)
{
    std::ifstream in(path, std::ios::binary);
    if (!in)
        return false;
    std::ostringstream os;
    os << in.rdbuf();
    out = os.str();
    return true;
}

bool startsWithEncryptedMagic(const std::string& text)
{
    const std::size_t nl = text.find('\n');
    std::string first = text.substr(0, nl);
    if (!first.empty() && first.back() == '\r')
        first.pop_back();
    return first == kEncryptedMagic;
}

bool parseEnvelope(const std::string& text, std::map<std::string, std::string>& out)
{
    std::istringstream in(text);
    std::string line;
    bool first = true;
    while (std::getline(in, line))
    {
        if (first)
        {
            if (!line.empty() && line.back() == '\r')
                line.pop_back();
            if (line != kEncryptedMagic)
                return false;
            first = false;
            continue;
        }

        const std::string trimmed = trimCopy(line);
        if (trimmed.empty() || trimmed[0] == '#')
            continue;

        const std::size_t eq = trimmed.find('=');
        if (eq == std::string::npos)
            return false;
        out[lower(trimCopy(trimmed.substr(0, eq)))] = trimCopy(trimmed.substr(eq + 1));
    }
    return !first;
}

bool encryptConfig(const std::string& plain, const std::string& password,
                   std::string& out, std::string& err)
{
    std::vector<std::uint8_t> salt = secureRandomBytes(kSaltBytes);
    std::vector<std::uint8_t> nonce = secureRandomBytes(kNonceBytes);
    if (salt.size() != kSaltBytes || nonce.size() != kNonceBytes)
    {
        err = "secure random generator is not available";
        return false;
    }

    Sha256Digest key = pbkdf2HmacSha256(password, salt.data(), salt.size(),
                                          kKdfIterations);

    std::string cipher = plain;
    i2p::crypto::chacha::Chacha20State state;
    i2p::crypto::chacha::Chacha20Init(state, nonce.data(), key.data(), 0);
    i2p::crypto::chacha::Chacha20Encrypt(
        state, reinterpret_cast<std::uint8_t*>(&cipher[0]), cipher.size());

    std::string macInput(reinterpret_cast<const char*>(nonce.data()), nonce.size());
    macInput.append(cipher);

    Sha256Digest mac = hmacSha256(key.data(), key.size(),
                                  macInput.data(), macInput.size());

    std::ostringstream os;
    os << kEncryptedMagic << "\n"
       << "version = 1\n"
       << "kdf = pbkdf2-hmac-sha256\n"
       << "iterations = " << kKdfIterations << "\n"
       << "salt = " << base64Encode(salt) << "\n"
       << "nonce = " << base64Encode(nonce) << "\n"
       << "mac = " << base64Encode(mac.data(), mac.size()) << "\n"
       << "data = " << base64Encode(
              reinterpret_cast<const std::uint8_t*>(cipher.data()), cipher.size())
       << "\n";
    out = os.str();

    secureZero(key.data(), key.size());
    secureZero(mac.data(), mac.size());
    secureWipe(cipher);
    secureWipe(macInput);
    return true;
}

bool decryptConfig(const std::string& text, const std::string& password,
                   std::string& out, std::string& err)
{
    std::map<std::string, std::string> fields;
    if (!parseEnvelope(text, fields))
    {
        err = "damaged encrypted config header";
        return false;
    }

    if (fields["version"] != "1" || fields["kdf"] != "pbkdf2-hmac-sha256")
    {
        err = "unsupported encrypted config format";
        return false;
    }

    unsigned iterations = 0;
    if (!parseUInt(fields["iterations"], iterations, 10000000) || iterations < 1000)
    {
        err = "invalid KDF iteration count";
        return false;
    }

    std::vector<std::uint8_t> salt;
    std::vector<std::uint8_t> nonce;
    std::vector<std::uint8_t> expectedMac;
    std::vector<std::uint8_t> cipher;
    if (!base64Decode(fields["salt"], salt) ||
        !base64Decode(fields["nonce"], nonce) ||
        !base64Decode(fields["mac"], expectedMac) ||
        !base64Decode(fields["data"], cipher))
    {
        err = "damaged encrypted config";
        return false;
    }

    if (salt.size() < 8 || nonce.size() != kNonceBytes ||
        expectedMac.size() != 32 || cipher.empty())
    {
        err = "invalid encrypted config sizes";
        return false;
    }

    Sha256Digest key = pbkdf2HmacSha256(password, salt.data(), salt.size(),
                                        iterations);

    std::string macInput(reinterpret_cast<const char*>(nonce.data()), nonce.size());
    macInput.append(reinterpret_cast<const char*>(cipher.data()), cipher.size());
    Sha256Digest actualMac = hmacSha256(key.data(), key.size(),
                                        macInput.data(), macInput.size());

    const std::string actual(reinterpret_cast<const char*>(actualMac.data()),
                             actualMac.size());
    const std::string expected(reinterpret_cast<const char*>(expectedMac.data()),
                               expectedMac.size());
    const bool macOk = constantTimeEquals(actual, expected);

    if (macOk)
    {
        i2p::crypto::chacha::Chacha20State state;
        i2p::crypto::chacha::Chacha20Init(state, nonce.data(), key.data(), 0);
        i2p::crypto::chacha::Chacha20Encrypt(
            state, cipher.data(), cipher.size());
        out.assign(reinterpret_cast<const char*>(cipher.data()), cipher.size());
    }
    else
    {
        err = "wrong config password or damaged config";
    }

    secureZero(key.data(), key.size());
    secureZero(actualMac.data(), actualMac.size());
    secureWipe(macInput);
    secureWipe(cipher);
    return macOk;
}

} // namespace

Config defaultConfig()
{
    return Config{};
}

std::string defaultConfigPath(const char* argv0)
{
    return joinPath(executableDir(argv0), "trigande.conf");
}

bool configIsEncrypted(const std::string& path)
{
    std::string text;
    if (!readWholeFile(path, text))
        return false;
    return startsWithEncryptedMagic(text);
}

LoadResult loadConfig(const std::string& path, const std::string& password,
                      Config& cfg, std::string& err)
{
    cfg = defaultConfig();
    cfg.path = path;
    cfg.configPassword = password;

    std::string stored;
    if (!readWholeFile(path, stored))
    {
        err = "can't open " + path;
        return LoadResult::Missing;
    }

    std::string plain;
    if (startsWithEncryptedMagic(stored))
    {
        if (password.empty())
        {
            err = "config is encrypted; password is required";
            return LoadResult::NeedsPassword;
        }
        if (!decryptConfig(stored, password, plain, err))
            return LoadResult::Error;
        cfg.configEncrypted = true;
    }
    else
    {
        plain = stored;
        cfg.configEncrypted = !password.empty();
    }

    std::istringstream in(plain);
    std::string line;
    std::size_t lineNo = 0;
    while (std::getline(in, line))
    {
        ++lineNo;
        const std::string trimmed = trimCopy(line);
        if (trimmed.empty() || trimmed[0] == '#')
            continue;

        const std::size_t eq = trimmed.find('=');
        if (eq == std::string::npos)
        {
            std::ostringstream os;
            os << path << ":" << lineNo << ": expected key = value";
            err = os.str();
            return LoadResult::Error;
        }

        const std::string key = lower(trimCopy(trimmed.substr(0, eq)));
        const std::string value = trimCopy(trimmed.substr(eq + 1));

        bool b = false;
        unsigned u = 0;

        if (key == "nick")
            cfg.nick = value;
        else if (key == "private_key")
            cfg.privateKey = value;
        else if (key == "sam_host")
            cfg.samHost = value;
        else if (key == "sam_port")
        {
            if (!parseUInt(value, u, 65535))
                return LoadResult::Error;
            cfg.samPort = static_cast<std::uint16_t>(u);
        }
        else if (key == "sam_session")
            cfg.samSession = value;
        else if (key == "sam_signature_type")
            cfg.samSignatureType = value;
        else if (key == "dh_bits")
        {
            if (!parseUInt(value, u, 65536) || u < 64)
                return LoadResult::Error;
            cfg.dhBits = u;
        }
        else if (key == "group_bits")
        {
            if (!parseUInt(value, u, 4096) || u < 16)
                return LoadResult::Error;
            cfg.groupBits = u;
        }
        else if (key == "secret_bits")
        {
            if (!parseUInt(value, u, 65536) || u < 64)
                return LoadResult::Error;
            cfg.secretBits = u;
        }
        else if (key == "rekey_secret_bits")
        {
            if (!parseUInt(value, u, 65536) || u < 64)
                return LoadResult::Error;
            cfg.rekeySecretBits = u;
        }
        else if (key == "max_peer_dh_bits")
        {
            if (!parseUInt(value, u, 65536))
                return LoadResult::Error;
            cfg.maxPeerDhBits = u;
        }
        else if (key == "allow_huge_dh")
        {
            if (!parseBool(value, b))
                return LoadResult::Error;
            cfg.allowHugeDh = b;
        }
        else if (key == "server_mode")
        {
            if (!parseBool(value, b))
                return LoadResult::Error;
            cfg.serverMode = b;
        }
        else if (key == "daemon_mode")
        {
            if (!parseBool(value, b))
                return LoadResult::Error;
            cfg.daemonMode = b;
        }
        else if (key == "sandbox")
        {
            if (!parseBool(value, b))
                return LoadResult::Error;
            cfg.sandboxEnabled = b;
        }
        else if (key == "relay_version")
        {
            if (!parseUInt(value, u, 3) || (u != 2 && u != 3))
                return LoadResult::Error;
            cfg.relayVersion = u;
        }
        else if (key == "relay_limit")
        {
            if (!parseUInt(value, u, 100000))
                return LoadResult::Error;
            cfg.relayLimit = u;
        }
        else if (key == "relay_anonymous")
        {
            if (!parseBool(value, b))
                return LoadResult::Error;
            cfg.relayAnonymous = b;
        }
        else if (key == "relay_ask_plain")
        {
            if (!parseBool(value, b))
                return LoadResult::Error;
            cfg.relayAskPlain = b;
        }
        else if (key == "relay_password")
            cfg.relayPassword = value;
        /* Unknown keys are ignored so an older binary can read a newer file. */
    }

    if (cfg.samHost.empty() || cfg.samPort == 0 || cfg.samSignatureType.empty())
    {
        err = path + ": sam_host/sam_port/sam_signature_type must not be empty";
        return LoadResult::Error;
    }

    secureWipe(plain);
    return LoadResult::Ok;
}

bool saveConfig(Config& cfg, std::string& err)
{
    if (cfg.configEncrypted && cfg.configPassword.empty())
    {
        err = "refusing to store an encrypted config without a password";
        return false;
    }

    std::ostringstream os;
    os << "# TriMessage / Trigande config\n"
       << "# Created automatically.  Keep this file private: private_key is a\n"
       << "# full I2P destination with its private keys.\n"
       << "\n"
       << "nick = " << cfg.nick << "\n"
       << "private_key = " << cfg.privateKey << "\n"
       << "\n"
       << "# SAM bridge settings (individual for every client).\n"
       << "sam_host = " << cfg.samHost << "\n"
       << "sam_port = " << cfg.samPort << "\n"
       << "sam_session = " << cfg.samSession << "\n"
       << "sam_signature_type = " << cfg.samSignatureType << "\n"
       << "\n"
       << "# DH sizes.  dh_bits is the group; secret_bits is the private exponent.\n"
       << "dh_bits = " << cfg.dhBits << "\n"
       << "group_bits = " << cfg.groupBits << "\n"
       << "secret_bits = " << cfg.secretBits << "\n"
       << "rekey_secret_bits = " << cfg.rekeySecretBits << "\n"
       << "\n"
       << "# Warn / ask before talking to a peer with a group larger than this.\n"
       << "max_peer_dh_bits = " << cfg.maxPeerDhBits << "\n"
       << "allow_huge_dh = " << b2s(cfg.allowHugeDh) << "\n"
       << "\n"
       << "# Local process isolation.  Disable only for debugging.\n"
       << "sandbox = " << b2s(cfg.sandboxEnabled) << "\n"
       << "\n"
       << "# Relay server mode.\n"
       << "server_mode = " << b2s(cfg.serverMode) << "\n"
       << "daemon_mode = " << b2s(cfg.daemonMode) << "\n"
       << "relay_version = " << cfg.relayVersion << "\n"
       << "relay_limit = " << cfg.relayLimit << "\n"
       << "relay_anonymous = " << b2s(cfg.relayAnonymous) << "\n"
       << "relay_ask_plain = " << b2s(cfg.relayAskPlain) << "\n"
       << "# Empty means the relay is open.  This is the group password,\n"
       << "# not the password that encrypts this config file.\n"
       << "relay_password = " << cfg.relayPassword << "\n";

    const std::string plain = os.str();

    std::string payload = plain;
    if (!cfg.configPassword.empty())
    {
        std::string encrypted;
        if (!encryptConfig(plain, cfg.configPassword, encrypted, err))
        {
            secureWipe(payload);
            return false;
        }
        payload = std::move(encrypted);
    }

    const std::string tmp = cfg.path + ".tmp";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out)
        {
            err = "can't write " + tmp;
            secureWipe(payload);
            return false;
        }
        out.write(payload.data(), static_cast<std::streamsize>(payload.size()));
        if (!out.flush())
        {
            err = "can't flush " + tmp;
            out.close();
            removeFile(tmp);
            secureWipe(payload);
            return false;
        }
        out.close();
        if (!out)
        {
            err = "can't finish writing " + tmp;
            removeFile(tmp);
            secureWipe(payload);
            return false;
        }
    }

    setFileMode0600(tmp);
    if (!replaceFile(tmp, cfg.path))
    {
        err = "can't replace " + cfg.path;
        removeFile(tmp);
        secureWipe(payload);
        return false;
    }

    cfg.configEncrypted = !cfg.configPassword.empty();
    secureWipe(payload);
    return true;
}

} // namespace TriMessage
