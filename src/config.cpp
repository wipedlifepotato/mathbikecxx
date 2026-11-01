#include "config.h"

#include "common/util.h"

#include <cstdio>
#include <fstream>
#include <sstream>
#include <sys/stat.h>

namespace TriMessage
{

namespace
{

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

} // namespace

Config defaultConfig()
{
    return Config{};
}

std::string defaultConfigPath(const char* argv0)
{
    return joinPath(executableDir(argv0), "trigande.conf");
}

LoadResult loadConfig(const std::string& path, Config& cfg, std::string& err)
{
    cfg = defaultConfig();
    cfg.path = path;

    std::ifstream in(path);
    if (!in)
    {
        err = "can't open " + path;
        return LoadResult::Missing;
    }

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

    return LoadResult::Ok;
}

bool saveConfig(const Config& cfg, std::string& err)
{
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
       << "# Relay server mode.\n"
       << "server_mode = " << b2s(cfg.serverMode) << "\n"
       << "daemon_mode = " << b2s(cfg.daemonMode) << "\n"
       << "relay_version = " << cfg.relayVersion << "\n"
       << "relay_limit = " << cfg.relayLimit << "\n"
       << "relay_anonymous = " << b2s(cfg.relayAnonymous) << "\n"
       << "relay_ask_plain = " << b2s(cfg.relayAskPlain) << "\n"
       << "# Empty means the relay is open.  This is the group password.\n"
       << "relay_password = " << cfg.relayPassword << "\n";

    const std::string tmp = cfg.path + ".tmp";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out)
        {
            err = "can't write " + tmp;
            return false;
        }
        out << os.str();
        if (!out.flush())
        {
            err = "can't flush " + tmp;
            return false;
        }
    }

    ::chmod(tmp.c_str(), 0600);
    if (std::rename(tmp.c_str(), cfg.path.c_str()) != 0)
    {
        err = "can't replace " + cfg.path;
        std::remove(tmp.c_str());
        return false;
    }
    return true;
}

} // namespace TriMessage
