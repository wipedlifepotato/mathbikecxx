/*
 * TriMessage - a small I2P chat bike.
 *
 * Entry point: command line parsing (getopt_long), config bootstrap and mode
 * selection.  The chat client lives in src/client, the relay server lives in
 * src/server, and the shared wire format lives in src/common.
 *
 * Build: make Trie
 */

#include <cerrno>
#include <csignal>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <getopt.h>
#include <iostream>
#include <string>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>

#include "i2psam/i2psam.h"

#include "config.h"
#include "common/util.h"
#include "client/client.h"
#include "server/relay.h"

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
    OptRelayVersion,
    OptRelayLimit,
    OptAnonymous,
    OptNoAskPlain,
    OptPassword
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
        << "  -h, --help                 this help\n"
        << "\n"
        << "The config file is created on the first run.  It stores the private\n"
        << "key, nickname, SAM settings and all of the options above.\n";
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

bool persistConfig(const Config& cfg)
{
    std::string err;
    if (!saveConfig(cfg, err))
    {
        std::cerr << "can't save config: " << err << std::endl;
        return false;
    }
    return true;
}

void daemonize(const std::string& logPath)
{
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
    ::chdir("/");

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
}

} // namespace

int main(int argc, char** argv)
{
    std::string optConfigPath;
    std::string optHost;
    std::string optNick;
    std::string optPriv;
    std::string optSession;
    std::string optPassword;
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
    bool optAnonymous = false;
    bool optNoAskPlain = false;
    bool havePassword = false;

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
        {"relay-version", required_argument, nullptr, OptRelayVersion},
        {"relay-limit", required_argument, nullptr, OptRelayLimit},
        {"anonymous", no_argument, nullptr, OptAnonymous},
        {"no-ask-plain", no_argument, nullptr, OptNoAskPlain},
        {"password", required_argument, nullptr, OptPassword},
        {"relay-password", required_argument, nullptr, OptPassword},
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

    const std::string configPath =
        optConfigPath.empty() ? defaultConfigPath(argv[0]) : optConfigPath;

    Config cfg;
    std::string loadErr;
    const LoadResult loaded = loadConfig(configPath, cfg, loadErr);
    if (loaded == LoadResult::Error)
    {
        std::cerr << "config error: " << loadErr << std::endl;
        return 1;
    }
    cfg.path = configPath;
    bool dirty = (loaded == LoadResult::Missing);

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

    const std::string originalNick = cfg.nick;
    cfg.nick = sanitizeNick(cfg.nick);
    if (cfg.nick != originalNick)
        dirty = true;

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
        daemonize(joinPath(executableDir(argv[0]), "trigande.log"));

    /*
     * Handle Ctrl+C/Ctrl+D as a normal shutdown so peers receive BYE instead
     * of waiting for the heartbeat timeout.  The signals are blocked before
     * any thread is created; one thread waits for them.  Until the client or
     * the relay has been constructed, the same thread exits immediately so a
     * Ctrl+C during a slow SAM handshake does not hang the terminal.
     */
    sigset_t stopSignals;
    sigemptyset(&stopSignals);
    sigaddset(&stopSignals, SIGINT);
    sigaddset(&stopSignals, SIGTERM);
    sigprocmask(SIG_BLOCK, &stopSignals, nullptr);
    std::signal(SIGPIPE, SIG_IGN);

    std::atomic<Client*> clientPtr{nullptr};
    std::atomic<RelayServer*> serverPtr{nullptr};

    std::thread signalThread([&clientPtr, &serverPtr, stopSignals]() {
        int sig = 0;
        if (sigwait(&stopSignals, &sig) != 0)
            return;
        if (Client* client = clientPtr.load())
            client->ShutdownNow();
        else if (RelayServer* server = serverPtr.load())
            server->ShutdownNow();
        else
            ::_exit(0);
    });
    signalThread.detach();

    try
    {
        if (cfg.serverMode)
        {
            RelayServer server(cfg);
            serverPtr.store(&server);
            server.Run();
            serverPtr.store(nullptr);
        }
        else
        {
            Client client(cfg);
            clientPtr.store(&client);
            client.Run();
            clientPtr.store(nullptr);
        }
    }
    catch (const std::exception& e)
    {
        std::cerr << "fatal: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
