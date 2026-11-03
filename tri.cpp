/*
 * TriMessage - a small I2P chat bike.
 *
 * Entry point: command line parsing (getopt_long), config bootstrap and mode
 * selection.  The chat client lives in src/client, the relay server lives in
 * src/server, and the shared wire format lives in src/common.
 *
 * Build: make Trie
 */

#if defined(_WIN32)
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#undef WINVER
#define WINVER 0x0A00
#endif

#include <cerrno>
#include <csignal>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <getopt.h>
#include <iostream>
#include <string>
#include <thread>

#if defined(_WIN32)
#include <winsock2.h>
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include "i2psam/i2psam.h"

#include "config.h"
#include "common/platform.h"
#include "common/util.h"
#include "security/sandbox.h"
#include "client/client.h"
#include "server/relay.h"

#if defined(_WIN32) || defined(__APPLE__)
#warning "TriMessage: this platform build is NOT fully isolated. Use it only for testing; Linux/OpenBSD are the supported secure targets."
#endif

using namespace TriMessage;

namespace
{

enum
{
    OptDhBits = 1000,
    OptGroupBits,
    OptSecretBits,
    OptMaxPeerDhBits,
    OptAllowHugeDh,
    OptAutoAccept,
    OptNoAutoAccept,
    OptWaitAcceptTime,
    OptFloodWindow,
    OptFloodRepeat,
    OptFloodGarbage,
    OptFloodDh,
    OptFloodMessage,
    OptBanInitial,
    OptBanMax,
    OptBanMemory,
    OptNoColor,
    OptRelayVersion,
    OptRelayLimit,
    OptAnonymous,
    OptNoAskPlain,
    OptPassword,
    OptConfigPassword,
    OptNoConfigPassword,
    OptNoSandbox
};

void printUsage(const char* argv0)
{
    std::cout
        << "Usage: " << argv0 << " [options]\n"
        << "\n"
        << "Client:\n"
        << "  -H, --host <host>          SAM host (default 127.0.0.1)\n"
        << "  -P, --port <port>          SAM TCP port (default 7656)\n"
        << "  -n, --nick <name>          nickname\n"
        << "  -k, --priv <destination>   private destination to reuse\n"
        << "  -s, --session <name>       SAM session name\n"
        << "\n"
        << "Acceptance and anti-flood:\n"
        << "      --auto-accept          accept incoming peers without asking\n"
        << "      --no-auto-accept       incoming peers need /accept first\n"
        << "      --wait-accept-time <s> seconds to wait for /accept (default 45)\n"
        << "      --flood-window <s>     anti-flood window (default 10)\n"
        << "      --flood-repeat <n>     repeated messages before a kick (default 6)\n"
        << "      --flood-garbage <n>    garbage frames before a kick (default 8)\n"
        << "      --flood-dh <n>         DH requests per window before a kick (default 4)\n"
        << "      --flood-messages <n>   messages per window before a kick (default 30)\n"
        << "      --ban-initial <s>      first ban duration (default 60)\n"
        << "      --ban-max <s>          maximum ban duration (default 86400)\n"
        << "      --ban-memory <mb>      maximum memory used by bans (default 4)\n"
        << "      --no-color             disable ANSI colours\n"
        << "\n"
        << "Relay server:\n"
        << "  -S, --server               run as a relay chat server\n"
        << "  -D, --daemon               detach and log to trigande.log\n"
        << "      --relay-version <n>    relay protocol: 2 = encrypted, 3 = plaintext\n"
        << "      --relay-limit <n>      maximum number of participants\n"
        << "      --anonymous            hide real participant fingerprints\n"
        << "      --no-ask-plain         do not ask before joining a version 3 relay\n"
        << "      --password <pass>      group password (relay and client)\n"
        << "\n"
        << "Crypto:\n"
        << "      --dh-bits <n>          DH group size (default 1024)\n"
        << "      --group-bits <n>       generator size (default 128)\n"
        << "      --secret-bits <n>      private exponent size (default 256)\n"
        << "      --max-peer-dh-bits <n> warn above this peer DH size (default 8192)\n"
        << "      --allow-huge-dh        accept huge peer DH keys without asking\n"
        << "\n"
        << "Other:\n"
        << "  -c, --config <path>        config file (default: next to the binary)\n"
        << "      --config-password <p>  password that encrypts the config file\n"
        << "      --no-config-password   store the config in plaintext\n"
        << "      --no-sandbox           disable local process isolation\n"
        << "  -h, --help                 this help\n"
        << "\n"
        << "The config file is created on the first run.  It stores the private\n"
        << "key, nickname, SAM settings and all of the options above.  If a TTY\n"
        << "is available, the first run asks for a password and encrypts it.\n"
        << "The relay chat password (--password) is a different secret.\n";
}

bool generatePrivateKey(Config& cfg)
{
    try
    {
        SAM::StreamSession tmp("TriKeyGen-" + randomHex(4), cfg.samHost, cfg.samPort);
        auto generated = tmp.destGenerate();
        if (!generated.isOk || generated.value.pub.empty() || generated.value.priv.empty())
        {
            std::cerr << "warning: SAM did not generate a private key" << std::endl;
            return false;
        }
        cfg.privateKey = generated.value.priv;
        /* DEST GENERATE without SIGNATURE_TYPE returns DSA_SHA1. */
        cfg.samSignatureType = "DSA_SHA1";
        std::cout << "generated a new private key (fingerprint "
                  << shortFp(fingerprintOf(generated.value.pub)) << ")" << std::endl;
        return true;
    }
    catch (const std::exception& e)
    {
        std::cerr << "warning: can't generate a private key: " << e.what() << std::endl;
        return false;
    }
}

bool persistConfig(Config& cfg)
{
    std::string err;
    if (!saveConfig(cfg, err))
    {
        std::cerr << "can't save config: " << err << std::endl;
        return false;
    }
    return true;
}

void daemonize(const std::string& logPath, const std::string& appDir)
{
#if defined(_WIN32)
    (void)logPath;
    (void)appDir;
    std::cerr << "warning: --daemon is not supported on Windows; "
                 "continuing in the foreground" << std::endl;
#else
    pid_t pid = ::fork();
    if (pid < 0)
    {
        std::cerr << "can't fork: " << std::strerror(errno) << std::endl;
        std::_Exit(1);
    }
    if (pid > 0)
        std::_Exit(0);

    if (::setsid() < 0)
        std::_Exit(1);

    pid = ::fork();
    if (pid < 0)
        std::_Exit(1);
    if (pid > 0)
        std::_Exit(0);

    ::umask(027);
    ::chdir(appDir.c_str());

    const int logFd = ::open(logPath.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (logFd >= 0)
    {
        ::dup2(logFd, STDOUT_FILENO);
        ::dup2(logFd, STDERR_FILENO);
        if (logFd > STDERR_FILENO)
            ::close(logFd);
    }

    const int nullFd = ::open("/dev/null", O_RDONLY);
    if (nullFd >= 0)
    {
        ::dup2(nullFd, STDIN_FILENO);
        if (nullFd > STDIN_FILENO)
            ::close(nullFd);
    }
#endif
}

bool isAbsolutePath(const std::string& path)
{
#if defined(_WIN32)
    if (path.size() >= 2 &&
        ((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) &&
        path[1] == ':')
        return true;
    if (path.size() >= 2 &&
        (path[0] == '\\' || path[0] == '/') &&
        (path[1] == '\\' || path[1] == '/'))
        return true;
    return false;
#else
    return !path.empty() && path[0] == '/';
#endif
}

std::atomic<Client*> g_clientPtr{nullptr};
std::atomic<RelayServer*> g_serverPtr{nullptr};

#if defined(_WIN32)
BOOL WINAPI consoleCtrlHandler(DWORD type)
{
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT ||
        type == CTRL_CLOSE_EVENT || type == CTRL_SHUTDOWN_EVENT)
    {
        if (Client* client = g_clientPtr.load())
            client->ShutdownNow();
        else if (RelayServer* server = g_serverPtr.load())
            server->ShutdownNow();
        else
            ::_Exit(0);
        return TRUE;
    }
    return FALSE;
}
#endif

} // namespace

int main(int argc, char** argv)
{
    std::string optConfigPath;
    std::string optHost;
    std::string optNick;
    std::string optPriv;
    std::string optSession;
    std::string optPassword;
    std::string optConfigPassword;
    int optPort = -1;
    unsigned optDhBits = 0;
    unsigned optGroupBits = 0;
    unsigned optSecretBits = 0;
    unsigned optMaxPeerDhBits = 0;
    unsigned optRelayVersion = 0;
    unsigned optRelayLimit = 0;
    bool haveMaxPeerDhBits = false;
    bool optServer = false;
    bool optDaemon = false;
    bool optAllowHugeDh = false;
    bool optAutoAccept = false;
    bool haveAutoAccept = false;
    bool optNoColor = false;
    unsigned optWaitAcceptTime = 0;
    unsigned optFloodWindow = 0;
    unsigned optFloodRepeat = 0;
    unsigned optFloodGarbage = 0;
    unsigned optFloodDh = 0;
    unsigned optFloodMessage = 0;
    unsigned optBanInitial = 0;
    unsigned optBanMax = 0;
    unsigned optBanMemory = 0;
    bool haveFloodRepeat = false;
    bool haveFloodGarbage = false;
    bool haveFloodDh = false;
    bool haveFloodMessage = false;
    bool haveBanMemory = false;
    bool optAnonymous = false;
    bool optNoAskPlain = false;
    bool havePassword = false;
    bool haveConfigPassword = false;
    bool optNoConfigPassword = false;
    bool optNoSandbox = false;

    static const option longOptions[] = {
        {"help", no_argument, nullptr, 'h'},
        {"config", required_argument, nullptr, 'c'},
        {"host", required_argument, nullptr, 'H'},
        {"port", required_argument, nullptr, 'P'},
        {"nick", required_argument, nullptr, 'n'},
        {"priv", required_argument, nullptr, 'k'},
        {"session", required_argument, nullptr, 's'},
        {"server", no_argument, nullptr, 'S'},
        {"daemon", no_argument, nullptr, 'D'},
        {"dh-bits", required_argument, nullptr, OptDhBits},
        {"group-bits", required_argument, nullptr, OptGroupBits},
        {"secret-bits", required_argument, nullptr, OptSecretBits},
        {"max-peer-dh-bits", required_argument, nullptr, OptMaxPeerDhBits},
        {"allow-huge-dh", no_argument, nullptr, OptAllowHugeDh},
        {"auto-accept", no_argument, nullptr, OptAutoAccept},
        {"no-auto-accept", no_argument, nullptr, OptNoAutoAccept},
        {"wait-accept-time", required_argument, nullptr, OptWaitAcceptTime},
        {"flood-window", required_argument, nullptr, OptFloodWindow},
        {"flood-repeat", required_argument, nullptr, OptFloodRepeat},
        {"flood-garbage", required_argument, nullptr, OptFloodGarbage},
        {"flood-dh", required_argument, nullptr, OptFloodDh},
        {"flood-messages", required_argument, nullptr, OptFloodMessage},
        {"ban-initial", required_argument, nullptr, OptBanInitial},
        {"ban-max", required_argument, nullptr, OptBanMax},
        {"ban-memory", required_argument, nullptr, OptBanMemory},
        {"no-color", no_argument, nullptr, OptNoColor},
        {"relay-version", required_argument, nullptr, OptRelayVersion},
        {"relay-limit", required_argument, nullptr, OptRelayLimit},
        {"anonymous", no_argument, nullptr, OptAnonymous},
        {"no-ask-plain", no_argument, nullptr, OptNoAskPlain},
        {"password", required_argument, nullptr, OptPassword},
        {"relay-password", required_argument, nullptr, OptPassword},
        {"config-password", required_argument, nullptr, OptConfigPassword},
        {"no-config-password", no_argument, nullptr, OptNoConfigPassword},
        {"no-sandbox", no_argument, nullptr, OptNoSandbox},
        {nullptr, 0, nullptr, 0}
    };

    int opt = 0;
    while ((opt = ::getopt_long(argc, argv, "hc:H:P:n:k:s:SD", longOptions, nullptr)) != -1)
    {
        try
        {
            switch (opt)
            {
            case 'h':
                printUsage(argv[0]);
                return 0;
            case 'c':
                optConfigPath = optarg;
                break;
            case 'H':
                optHost = optarg;
                break;
            case 'P':
                optPort = std::stoi(optarg);
                break;
            case 'n':
                optNick = optarg;
                break;
            case 'k':
                optPriv = optarg;
                break;
            case 's':
                optSession = optarg;
                break;
            case 'S':
                optServer = true;
                break;
            case 'D':
                optDaemon = true;
                break;
            case OptDhBits:
                optDhBits = static_cast<unsigned>(std::stoul(optarg));
                break;
            case OptGroupBits:
                optGroupBits = static_cast<unsigned>(std::stoul(optarg));
                break;
            case OptSecretBits:
                optSecretBits = static_cast<unsigned>(std::stoul(optarg));
                break;
            case OptMaxPeerDhBits:
                optMaxPeerDhBits = static_cast<unsigned>(std::stoul(optarg));
                haveMaxPeerDhBits = true;
                break;
            case OptAllowHugeDh:
                optAllowHugeDh = true;
                break;
            case OptAutoAccept:
                optAutoAccept = true;
                haveAutoAccept = true;
                break;
            case OptNoAutoAccept:
                optAutoAccept = false;
                haveAutoAccept = true;
                break;
            case OptWaitAcceptTime:
                optWaitAcceptTime = static_cast<unsigned>(std::stoul(optarg));
                break;
            case OptFloodWindow:
                optFloodWindow = static_cast<unsigned>(std::stoul(optarg));
                break;
            case OptFloodRepeat:
                optFloodRepeat = static_cast<unsigned>(std::stoul(optarg));
                haveFloodRepeat = true;
                break;
            case OptFloodGarbage:
                optFloodGarbage = static_cast<unsigned>(std::stoul(optarg));
                haveFloodGarbage = true;
                break;
            case OptFloodDh:
                optFloodDh = static_cast<unsigned>(std::stoul(optarg));
                haveFloodDh = true;
                break;
            case OptFloodMessage:
                optFloodMessage = static_cast<unsigned>(std::stoul(optarg));
                haveFloodMessage = true;
                break;
            case OptBanInitial:
                optBanInitial = static_cast<unsigned>(std::stoul(optarg));
                break;
            case OptBanMax:
                optBanMax = static_cast<unsigned>(std::stoul(optarg));
                break;
            case OptBanMemory:
                optBanMemory = static_cast<unsigned>(std::stoul(optarg));
                haveBanMemory = true;
                break;
            case OptNoColor:
                optNoColor = true;
                break;
            case OptRelayVersion:
                optRelayVersion = static_cast<unsigned>(std::stoul(optarg));
                break;
            case OptRelayLimit:
                optRelayLimit = static_cast<unsigned>(std::stoul(optarg));
                break;
            case OptAnonymous:
                optAnonymous = true;
                break;
            case OptNoAskPlain:
                optNoAskPlain = true;
                break;
            case OptPassword:
                optPassword = optarg;
                havePassword = true;
                break;
            case OptConfigPassword:
                optConfigPassword = optarg;
                haveConfigPassword = true;
                break;
            case OptNoConfigPassword:
                optNoConfigPassword = true;
                break;
            case OptNoSandbox:
                optNoSandbox = true;
                break;
            default:
                printUsage(argv[0]);
                return 2;
            }
        }
        catch (const std::exception&)
        {
            std::cerr << "invalid value for option: " << optarg << std::endl;
            return 2;
        }
    }

    if (optind < argc)
    {
        std::cerr << "unexpected argument: " << argv[optind] << " (try --help)" << std::endl;
        return 2;
    }

    const std::string appDir = executableDir(argv[0]);
    std::string configPath = optConfigPath.empty()
                                 ? joinPath(appDir, "trigande.conf")
                                 : optConfigPath;
    if (!isAbsolutePath(configPath))
        configPath = joinPath(appDir, configPath);

    if (!setWorkingDirectory(appDir))
        std::cerr << "warning: can't chdir to " << appDir << std::endl;

    const bool configExisted = fileExists(configPath);
    const bool configWasEncrypted = configExisted && configIsEncrypted(configPath);

    if (haveConfigPassword && optNoConfigPassword)
    {
        std::cerr << "--config-password and --no-config-password are mutually "
                     "exclusive" << std::endl;
        return 2;
    }
    if (optNoConfigPassword && configWasEncrypted)
    {
        std::cerr << "config is encrypted; --no-config-password cannot decrypt it. "
                     "Use --config-password, or /settings config_password - to "
                     "store it as plaintext." << std::endl;
        return 1;
    }

    std::string configPassword;
    if (optNoConfigPassword)
    {
        configPassword.clear();
    }
    else if (haveConfigPassword)
    {
        configPassword = optConfigPassword;
    }
    else if (const char* envPassword = std::getenv("TRIGANDE_CONFIG_PASSWORD"))
    {
        configPassword = envPassword;
    }
    else if (configWasEncrypted)
    {
        if (!isInteractiveStdin())
        {
            std::cerr << "config is encrypted; set TRIGANDE_CONFIG_PASSWORD or "
                         "use --config-password" << std::endl;
            return 1;
        }
        if (!askPassword("config password for " + configPath + ": ", configPassword))
            return 1;
    }
    else if (!configExisted && isInteractiveStdin())
    {
        std::cout << "The config file contains your I2P private key.\n"
                  << "It can be encrypted with a password (recommended).\n";
        std::string first;
        if (!askPassword("new config password (empty = no encryption): ", first))
            return 1;
        if (!first.empty())
        {
            std::string second;
            if (!askPassword("repeat config password: ", second) || first != second)
            {
                secureWipe(first);
                secureWipe(second);
                std::cerr << "passwords do not match" << std::endl;
                return 1;
            }
            secureWipe(second);
            configPassword = first;
        }
        secureWipe(first);
    }
    else if (!configExisted)
    {
        std::cerr << "warning: no TTY; the new config will be stored without "
                     "password encryption. Set TRIGANDE_CONFIG_PASSWORD to "
                     "encrypt it." << std::endl;
    }

    Config cfg;
    std::string loadErr;
    LoadResult loaded = loadConfig(configPath, configPassword, cfg, loadErr);
    if (loaded == LoadResult::NeedsPassword)
    {
        if (!isInteractiveStdin())
        {
            std::cerr << "config is encrypted; set TRIGANDE_CONFIG_PASSWORD or "
                         "use --config-password" << std::endl;
            return 1;
        }
        if (!askPassword("config password for " + configPath + ": ", configPassword))
            return 1;
        loaded = loadConfig(configPath, configPassword, cfg, loadErr);
    }
    if (loaded == LoadResult::Error)
    {
        std::cerr << "config error: " << loadErr << std::endl;
        return 1;
    }
    cfg.path = configPath;
    bool dirty = (loaded == LoadResult::Missing);

    /* A password given for an existing plaintext file re-encrypts it now. */
    if (loaded == LoadResult::Ok && !configPassword.empty() && !configWasEncrypted)
        dirty = true;

    if (!optHost.empty())
    {
        cfg.samHost = optHost;
        dirty = true;
    }
    if (optPort > 0 && optPort <= 65535)
    {
        cfg.samPort = static_cast<std::uint16_t>(optPort);
        dirty = true;
    }
    if (!optNick.empty())
    {
        cfg.nick = optNick;
        dirty = true;
    }
    if (!optPriv.empty())
    {
        cfg.privateKey = optPriv;
        dirty = true;
    }
    if (!optSession.empty())
    {
        cfg.samSession = optSession;
        dirty = true;
    }
    if (optServer)
    {
        cfg.serverMode = true;
        dirty = true;
    }
    if (optDaemon)
    {
        cfg.daemonMode = true;
        dirty = true;
    }
    if (optAllowHugeDh)
    {
        cfg.allowHugeDh = true;
        dirty = true;
    }
    if (haveAutoAccept)
    {
        cfg.autoAccept = optAutoAccept;
        dirty = true;
    }
    if (optWaitAcceptTime != 0)
    {
        if (optWaitAcceptTime < 5 || optWaitAcceptTime > 3600)
        {
            std::cerr << "--wait-accept-time must be 5..3600 seconds" << std::endl;
            return 2;
        }
        cfg.waitAcceptTimeSec = optWaitAcceptTime;
        dirty = true;
    }
    if (optFloodWindow != 0)
    {
        if (optFloodWindow < 1 || optFloodWindow > 3600)
        {
            std::cerr << "--flood-window must be 1..3600 seconds" << std::endl;
            return 2;
        }
        cfg.floodWindowSec = optFloodWindow;
        dirty = true;
    }
    if (haveFloodRepeat)
    {
        cfg.floodRepeatLimit = optFloodRepeat;
        dirty = true;
    }
    if (haveFloodGarbage)
    {
        cfg.floodGarbageLimit = optFloodGarbage;
        dirty = true;
    }
    if (haveFloodDh)
    {
        cfg.floodDhLimit = optFloodDh;
        dirty = true;
    }
    if (haveFloodMessage)
    {
        cfg.floodMessageLimit = optFloodMessage;
        dirty = true;
    }
    if (optBanInitial != 0)
    {
        if (optBanInitial < 1 || optBanInitial > 86400u * 30u)
        {
            std::cerr << "--ban-initial must be 1..2592000 seconds" << std::endl;
            return 2;
        }
        cfg.banInitialSeconds = optBanInitial;
        dirty = true;
    }
    if (optBanMax != 0)
    {
        if (optBanMax < 1 || optBanMax > 86400u * 365u)
        {
            std::cerr << "--ban-max must be 1..31536000 seconds" << std::endl;
            return 2;
        }
        cfg.banMaxSeconds = optBanMax;
        dirty = true;
    }
    if (haveBanMemory)
    {
        if (optBanMemory > 1024)
        {
            std::cerr << "--ban-memory must be 0..1024 MB" << std::endl;
            return 2;
        }
        cfg.banMemoryLimitMb = optBanMemory;
        dirty = true;
    }
    if (optNoColor)
    {
        cfg.colors = false;
        dirty = true;
    }
    if (optAnonymous)
    {
        cfg.relayAnonymous = true;
        dirty = true;
    }
    if (optNoAskPlain)
    {
        cfg.relayAskPlain = false;
        dirty = true;
    }
    if (havePassword)
    {
        cfg.relayPassword = optPassword;
        dirty = true;
    }
    if (optDhBits >= 64)
    {
        cfg.dhBits = optDhBits;
        dirty = true;
    }
    if (optGroupBits >= 16)
    {
        cfg.groupBits = optGroupBits;
        dirty = true;
    }
    if (optSecretBits >= 64)
    {
        cfg.secretBits = optSecretBits;
        dirty = true;
    }
    if (haveMaxPeerDhBits)
    {
        cfg.maxPeerDhBits = optMaxPeerDhBits;
        dirty = true;
    }
    if (optRelayVersion != 0)
    {
        if (optRelayVersion != 2 && optRelayVersion != 3)
        {
            std::cerr << "--relay-version must be 2 or 3" << std::endl;
            return 2;
        }
        cfg.relayVersion = optRelayVersion;
        dirty = true;
    }
    if (optRelayLimit != 0)
    {
        cfg.relayLimit = optRelayLimit;
        dirty = true;
    }
    if (optNoSandbox)
    {
        /* Runtime-only override: do not persist it, so a debug run does not
         * silently disable isolation forever. */
        cfg.sandboxEnabled = false;
    }

    const std::string originalNick = cfg.nick;
    if (cfg.nick.empty())
        cfg.nick = (cfg.serverMode ? "relay" : "user" + randomHex(2));
    else if (!isValidNick(cfg.nick))
    {
        std::cerr << "invalid nickname: only ASCII letters, digits, '_', '-' and "
                     "'.' are allowed (max 32 characters). "
                     "A non-Latin or lookalike nickname is not accepted."
                  << std::endl;
        return 2;
    }
    if (cfg.nick != originalNick)
        dirty = true;

    setColorEnabled(cfg.colors);
#if defined(_WIN32)
    if (cfg.colors)
    {
        HANDLE out = ::GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD mode = 0;
        if (out != INVALID_HANDLE_VALUE && ::GetConsoleMode(out, &mode))
            ::SetConsoleMode(out, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    }
#endif

    if (cfg.samSession.empty())
    {
        cfg.samSession = (cfg.serverMode ? "TriRelay-" : "TriMessage-") +
                         cfg.nick + "-" + randomHex(2);
        dirty = true;
    }

    if (cfg.privateKey.empty())
    {
        if (generatePrivateKey(cfg))
            dirty = true;
        else if (cfg.serverMode)
        {
            std::cerr << "the relay needs a persistent private key; start SAM and "
                         "run again" << std::endl;
            return 1;
        }
    }

    if (cfg.serverMode && !cfg.privateKey.empty() && cfg.samSignatureType.empty())
        cfg.samSignatureType = "DSA_SHA1";

    if (dirty)
    {
        if (!persistConfig(cfg))
            return 1;
        std::cout << (loaded == LoadResult::Missing ? "created " : "updated ")
                  << configPath << std::endl;
    }

    if (cfg.serverMode && cfg.daemonMode)
        daemonize(joinPath(appDir, "trigande.log"), appDir);

#if defined(_WIN32) || defined(__APPLE__)
    std::cerr
        << "\n"
        << "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"
        << "!! WARNING: this Windows/macOS build is NOT fully isolated.    !!\n"
        << "!! Use Linux or OpenBSD for real work.                        !!\n"
        << "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"
        << std::endl;
#endif

    if (cfg.sandboxEnabled)
    {
        SandboxOptions sandboxOptions;
        sandboxOptions.enabled = true;
        sandboxOptions.appDir = appDir;
        sandboxOptions.configPath = configPath;
        std::string sandboxErr;
        if (!sandboxApply(sandboxOptions, sandboxErr))
        {
            std::cerr << "[!] sandbox failed: " << sandboxErr << std::endl;
            std::cerr << "[!] refusing to run without isolation; use --no-sandbox "
                         "only if you understand the risk" << std::endl;
            return 1;
        }
        std::cout << "sandbox: " << sandboxPlatformName() << " active" << std::endl;
    }
    else
    {
        std::cerr << "[!] WARNING: sandbox is disabled; the process can access "
                     "files and start programs" << std::endl;
    }

    /*
     * Handle Ctrl+C/Ctrl+D as a normal shutdown so peers receive BYE instead
     * of waiting for the heartbeat timeout.  The signals are blocked before
     * any thread is created; one thread waits for them.  Until the client or
     * the relay has been constructed, the same thread exits immediately so a
     * Ctrl+C during a slow SAM handshake does not hang the terminal.
     */
#if defined(_WIN32)
    ::SetConsoleCtrlHandler(consoleCtrlHandler, TRUE);
#else
    sigset_t stopSignals;
    sigemptyset(&stopSignals);
    sigaddset(&stopSignals, SIGINT);
    sigaddset(&stopSignals, SIGTERM);
    sigprocmask(SIG_BLOCK, &stopSignals, nullptr);
    std::signal(SIGPIPE, SIG_IGN);

    std::thread signalThread([]() {
        sigset_t signals;
        sigemptyset(&signals);
        sigaddset(&signals, SIGINT);
        sigaddset(&signals, SIGTERM);
        int sig = 0;
        if (sigwait(&signals, &sig) != 0)
            return;
        if (Client* client = g_clientPtr.load())
            client->ShutdownNow();
        else if (RelayServer* server = g_serverPtr.load())
            server->ShutdownNow();
        else
            ::_exit(0);
    });
    signalThread.detach();
#endif

    try
    {
        if (cfg.serverMode)
        {
            RelayServer server(cfg);
            g_serverPtr.store(&server);
            server.Run();
            g_serverPtr.store(nullptr);
        }
        else
        {
            Client client(cfg);
            g_clientPtr.store(&client);
            client.Run();
            g_clientPtr.store(nullptr);
        }
    }
    catch (const std::exception& e)
    {
        std::cerr << "fatal: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
