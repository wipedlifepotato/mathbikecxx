#include "relay.h"

#include "common/frame.h"
#include "common/handshake.h"
#include "common/lines.h"
#include "common/protocol.h"
#include "common/util.h"

#include "alberthofman.h"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <deque>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <thread>

namespace TriMessage
{

struct RelayServer::Participant
{
    int id = 0;
    std::unique_ptr<SAM::I2pSocket> sock;
    std::string nick;
    std::string dest;
    std::string fp;       /* real fingerprint, kept server-side */
    std::string shownFp;  /* what other participants see */
    KeyMaterial key;
    bool plain = false;
    std::string pendingRx;
    std::atomic<bool> alive{true};

    std::mutex writeMutex;
    std::atomic<std::uint64_t> lastRx{0};

    /* Per-participant flood counters (protected by the reader thread). */
    std::uint64_t floodWindow = 0;
    unsigned floodMessages = 0;
    unsigned floodRepeats = 0;
    unsigned floodGarbage = 0;
    unsigned floodDh = 0;
    bool floodWarned = false;
    std::deque<std::string> recentMessages;

    bool sendLine(const std::string& line)
    {
        std::lock_guard<std::mutex> lk(writeMutex);
        if (!alive || !sock)
            return false;
        if (!sock->isOk())
        {
            alive = false;
            return false;
        }
        sock->write(line + "\n");
        if (!sock->isOk())
        {
            alive = false;
            return false;
        }
        return true;
    }

    void shutdown()
    {
        alive = false;
        std::lock_guard<std::mutex> lk(writeMutex);
        if (sock)
            sock->close();
    }
};

RelayServer::RelayServer(Config cfg)
    : m_config(std::move(cfg)),
      m_nick(sanitizeNick(m_config.nick.empty() ? "relay" : m_config.nick))
{
    if (m_config.samSession.empty())
        m_config.samSession = "TriRelay-" + m_nick + "-" + randomHex(2);
    m_sessionName = m_config.samSession;

    if (m_config.privateKey.empty())
        m_session = std::make_unique<SAM::StreamSession>(
            m_sessionName, m_config.samHost, m_config.samPort);
    else
    {
        std::string sigType = signatureTypeFromPrivate(m_config.privateKey);
        if (sigType.empty())
            sigType = m_config.samSignatureType;
        m_session = std::make_unique<SAM::StreamSession>(
            m_sessionName, m_config.samHost, m_config.samPort,
            m_config.privateKey, SAM_DEFAULT_I2P_OPTIONS, sigType);
    }

    if (!m_session || m_session->isSick())
        throw std::runtime_error("Can't init SAM stream session for the relay");

    m_myPub = publicDestinationFromPrivate(m_session->getMyDestination().priv);
    if (m_myPub.empty())
    {
        if (!m_config.privateKey.empty())
            m_myPub = m_session->getMyDestination().pub;
        else
        {
            auto generated = m_session->destGenerate();
            if (!generated.isOk || generated.value.priv.empty())
                throw std::runtime_error("Can't generate a persistent destination for the relay");

            m_config.privateKey = generated.value.priv;
            m_config.samSignatureType = "DSA_SHA1";
            m_config.samSession = m_sessionName + "-" + randomHex(2);
            m_sessionName = m_config.samSession;

            std::string err;
            if (!saveConfig(m_config, err))
                Log("[!] can't save the relay key: " + err);

            m_session.reset();
            m_session = std::make_unique<SAM::StreamSession>(
                m_sessionName, m_config.samHost, m_config.samPort,
                m_config.privateKey, SAM_DEFAULT_I2P_OPTIONS, "DSA_SHA1");
            if (!m_session || m_session->isSick())
                throw std::runtime_error("Can't init SAM session with generated relay destination");
            m_myPub = generated.value.pub;
        }
    }

    if (m_myPub.empty())
        throw std::runtime_error("SAM returned an empty relay destination");
    m_myFp = fingerprintOf(m_myPub);

    m_participantSecretBits = m_config.secretBits;
    if (m_participantSecretBits > 64)
        m_participantSecretBits -= 32; /* a little smaller than the config */
    m_participantSecretBits = std::max(64u, m_participantSecretBits);

    Log("relay is starting...");
    Log("nick:        " + m_nick);
    Log("destination: " + m_myPub);
    Log("fingerprint: " + m_myFp);
    Log("SAM:         " + m_session->getSAMHost() + ":" +
        std::to_string(m_session->getSAMPort()));
    Log("config:      " + m_config.path);
    Log("version:     " + std::to_string(m_config.relayVersion) +
        (m_config.relayVersion == kRelayPlain ? " (unencrypted)" : " (encrypted)"));
    Log("limit:       " + std::to_string(m_config.relayLimit) + " participants");
    Log("anonymous:   " + std::string(m_config.relayAnonymous ? "yes" : "no"));
    Log("password:    " + std::string(m_config.relayPassword.empty() ? "not set" : "required"));
    Log("dh bits:     " + std::to_string(m_config.dhBits) +
        " (participant secret " + std::to_string(m_participantSecretBits) + ")");

    m_janitorThread = std::thread(&RelayServer::JanitorLoop, this);
}

RelayServer::~RelayServer()
{
    m_running.store(false);

    std::vector<std::shared_ptr<Participant>> parts;
    {
        std::lock_guard<std::mutex> lk(m_partsMutex);
        for (auto& it : m_parts)
            parts.push_back(it.second);
        m_parts.clear();
    }
    for (auto& p : parts)
    {
        p->sendLine("BYE");
        p->shutdown();
    }

    if (m_janitorThread.joinable())
        m_janitorThread.detach();
}

void RelayServer::Log(const std::string& text)
{
    std::lock_guard<std::mutex> lk(m_logMutex);
    std::cout << "[relay] " << text << std::endl;
}

void RelayServer::ShutdownNow()
{
    Log("shutting down...");

    std::vector<std::shared_ptr<Participant>> parts;
    {
        std::lock_guard<std::mutex> lk(m_partsMutex);
        for (auto& it : m_parts)
            parts.push_back(it.second);
        m_parts.clear();
    }
    for (auto& p : parts)
    {
        p->sendLine("BYE");
        p->shutdown();
    }

    m_running.store(false);
    std::cout.flush();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    std::_Exit(0);
}

void RelayServer::Run()
{
    Log("listening for relay participants");

    while (m_running.load())
    {
        if (m_session->isSick())
        {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }

        auto result = m_session->accept(false);
        if (!result.isOk || !result.value)
        {
            if (!m_running.load())
                break;
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }

        HandleIncoming(std::move(result.value));
    }
}

bool RelayServer::HandleIncoming(std::unique_ptr<SAM::I2pSocket> sock)
{
    if (!m_running.load() || !sock)
        return false;

    auto sendLine = [&sock](const std::string& line) {
        sock->write(line + "\n");
        return sock->isOk();
    };

    try
    {
        LineReader reader(*sock);
        std::string line;
        if (!reader.readLine(line))
            return false;

        std::string samDest;
        for (;;)
        {
            if (line.rfind("STREAM STATUS", 0) == 0)
            {
                if (line.find("RESULT=OK") == std::string::npos)
                {
                    Log("[!] SAM accept failed: " + line);
                    return false;
                }
                if (!reader.readLine(line))
                    return false;
                continue;
            }

            if (line.rfind("HELLO ", 0) == 0)
                break;

            const std::size_t space = line.find(' ');
            samDest = trimCopy(space == std::string::npos ? line : line.substr(0, space));
            if (!looksLikeI2pDestination(samDest))
            {
                Log("[!] unexpected first line on accept (not a destination)");
                return false;
            }

            if (!reader.readLine(line))
                return false;
        }

        const std::size_t sp = line.find(' ');
        const std::string type = sp == std::string::npos ? line : line.substr(0, sp);
        const std::string payload = sp == std::string::npos ? "" : line.substr(sp + 1);
        if (type != "HELLO")
            return false;

        HsData cli;
        if (!decodeHs(payload, cli))
            return false;
        if (!isValidNick(cli.nick))
        {
            sendLine("HELLO_REJECT invalid nickname: ASCII letters, digits, "
                     "'_', '-' and '.' only");
            Log("[!] rejected a participant with an invalid nickname");
            return false;
        }
        if (cli.relayVersion != kRelayDirect)
        {
            sendLine("HELLO_REJECT direct clients only");
            return false;
        }
        if (cli.fp != fingerprintOf(cli.dest))
        {
            Log("[!] incoming HELLO has a bad fingerprint");
            return false;
        }
        if (!samDest.empty() && samDest != cli.dest)
        {
            Log("[!] incoming HELLO destination does not match the SAM peer");
            return false;
        }

        {
            std::lock_guard<std::mutex> lk(m_partsMutex);
            if (m_parts.size() >= m_config.relayLimit)
            {
                sendLine("HELLO_REJECT relay is full");
                Log("[!] rejected " + shortFp(cli.fp) + ": relay is full");
                return false;
            }
        }

        if (!m_config.allowHugeDh && m_config.maxPeerDhBits != 0 && !cli.p.empty())
        {
            unsigned pBits = 0;
            try
            {
                pBits = static_cast<unsigned>(
                    mpz_sizeinbase(mpz_class(cli.p).get_mpz_t(), 2));
            }
            catch (...)
            {
                sendLine("HELLO_REJECT invalid DH group");
                return false;
            }
            if (pBits > m_config.maxPeerDhBits)
            {
                sendLine("HELLO_REJECT DH key is too large");
                Log("[!] rejected " + shortFp(cli.fp) + ": " + std::to_string(pBits) +
                    "-bit DH group");
                return false;
            }
        }

        KeyMaterial key;
        bool plain = false;
        HsData srv;
        srv.nick = m_nick;
        srv.dest = m_myPub;
        srv.fp = m_myFp;
        srv.challenge = randomHex(16);
        srv.relayVersion = static_cast<std::uint8_t>(m_config.relayVersion);
        srv.role = "relay";
        srv.passwordRequired = !m_config.relayPassword.empty();

        if (m_config.relayVersion == kRelayPlain)
        {
            plain = true;
            srv.p.clear();
            srv.g.clear();
            srv.dhPub.clear();

            if (!sendLine("HELLO_ACK " + encodeHs(srv)))
                return false;

            const std::string transcript = makeTranscript(cli, srv);
            if (!reader.readLine(line))
                return false;

            const std::size_t sp2 = line.find(' ');
            const std::string type2 = sp2 == std::string::npos ? line : line.substr(0, sp2);
            const std::string payload2 = sp2 == std::string::npos ? "" : line.substr(sp2 + 1);

            if (srv.passwordRequired)
            {
                if (type2 != "AUTH" ||
                    !constantTimeEquals(
                        payload2,
                        makePasswordProof(m_config.relayPassword, transcript)))
                {
                    sendLine("AUTH_FAIL wrong password");
                    Log("[!] wrong password from " + shortFp(cli.fp));
                    return false;
                }
            }
            else if (line.find("AUTH_OK") != 0)
            {
                sendLine("AUTH_FAIL expected AUTH_OK");
                return false;
            }

            if (!sendLine("AUTH_OK"))
                return false;
        }
        else
        {
            if (cli.p.empty() || cli.g.empty() || cli.dhPub.empty())
            {
                sendLine("HELLO_REJECT missing DH data");
                return false;
            }

            DiffiHofman dh(mpz_class(cli.p), mpz_class(cli.g));
            const mpz_class myDhPub = dh.getPublicKey(m_participantSecretBits);

            srv.p = cli.p;
            srv.g = cli.g;
            srv.dhPub = myDhPub.get_str();

            if (!sendLine("HELLO_ACK " + encodeHs(srv)))
                return false;

            key = deriveKey(dh.getSharedKey(mpz_class(cli.dhPub)));
            const std::string transcript = makeTranscript(cli, srv);

            if (!reader.readLine(line))
                return false;
            const std::size_t sp2 = line.find(' ');
            const std::string type2 = sp2 == std::string::npos ? line : line.substr(0, sp2);
            const std::string payload2 = sp2 == std::string::npos ? "" : line.substr(sp2 + 1);
            const auto authParts = splitChar(payload2, ' ');
            const std::string dhProof = authParts.empty() ? std::string() : authParts[0];

            if (srv.passwordRequired)
            {
                const std::string passProof =
                    authParts.size() >= 2 ? authParts[1] : std::string();
                if (!constantTimeEquals(
                        passProof,
                        makePasswordProof(m_config.relayPassword, transcript)))
                {
                    sendLine("AUTH_FAIL wrong password");
                    Log("[!] wrong password from " + shortFp(cli.fp));
                    return false;
                }
            }

            if (type2 != "AUTH" ||
                !constantTimeEquals(dhProof, makeProof(key, transcript, "client")))
            {
                sendLine("AUTH_FAIL");
                Log("[!] authentication failed from " + shortFp(cli.fp));
                return false;
            }

            if (!sendLine("AUTH " + makeProof(key, transcript, "server")))
                return false;
            if (!reader.readLine(line))
                return false;
            if (line.find("AUTH_OK") != 0)
                return false;
        }

        if (!samDest.empty())
            cli.dest = samDest;

        const int id = m_nextId.fetch_add(1);
        auto p = std::make_shared<Participant>();
        p->id = id;
        p->sock = std::move(sock);
        p->nick = sanitizeNick(cli.nick);
        p->dest = cli.dest;
        p->fp = cli.fp;
        p->shownFp = m_config.relayAnonymous ? anonymousFingerprint(static_cast<std::uint64_t>(id))
                                             : cli.fp;
        p->key = key;
        p->plain = plain;
        p->pendingRx = reader.takeBuffer();
        p->lastRx.store(nowSeconds());

        {
            std::lock_guard<std::mutex> lk(m_partsMutex);
            m_parts[id] = p;
        }

        Log("[+] participant #" + std::to_string(id) + " \"" + p->nick +
            "\" fp=" + shortFp(p->shownFp) +
            (plain ? " (plaintext)" : " (encrypted)"));

        BroadcastRoster();

        std::size_t count = 0;
        {
            std::lock_guard<std::mutex> lk(m_partsMutex);
            count = m_parts.size();
        }
        std::thread(&RelayServer::ReaderLoop, this, p).detach();

        SendEvent(p, "SERVER",
                  "connected to relay version " +
                      std::to_string(m_config.relayVersion) +
                      (plain ? " (NO ENCRYPTION)" : "") +
                      "; participants: " + std::to_string(count),
                  m_myFp, m_nick);
        return true;
    }
    catch (const std::exception& e)
    {
        Log(std::string("[!] incoming handshake failed: ") + e.what());
        return false;
    }
}

bool RelayServer::SendEvent(const std::shared_ptr<Participant>& p,
                            const std::string& type,
                            const std::string& text,
                            const std::string& fromFp,
                            const std::string& fromNick)
{
    if (!p || !p->alive)
        return false;

    const std::string plain = makePlain(type, fromFp, fromNick, text);
    if (p->plain)
        return p->sendLine("MSG " + encodePlain(plain));
    return p->sendLine("MSG " + makeFrame(p->key, plain));
}

void RelayServer::BroadcastRoster()
{
    std::vector<std::shared_ptr<Participant>> parts;
    {
        std::lock_guard<std::mutex> lk(m_partsMutex);
        for (auto& it : m_parts)
            parts.push_back(it.second);
    }

    std::ostringstream roster;
    for (std::size_t i = 0; i < parts.size(); ++i)
    {
        if (i)
            roster << ';';
        roster << parts[i]->id << ':' << parts[i]->nick << ':' << parts[i]->shownFp;
    }
    const std::string text = roster.str();

    for (const auto& p : parts)
        SendEvent(p, "USERS", text, m_myFp, m_nick);
}

void RelayServer::BroadcastChat(const Participant& from, const std::string& text)
{
    std::vector<std::shared_ptr<Participant>> parts;
    {
        std::lock_guard<std::mutex> lk(m_partsMutex);
        for (auto& it : m_parts)
            parts.push_back(it.second);
    }

    for (const auto& p : parts)
    {
        if (p->id == from.id)
            continue;
        SendEvent(p, "CHAT", text, from.shownFp, from.nick);
    }
}

void RelayServer::ReaderLoop(std::shared_ptr<Participant> p)
{
    if (!p || !p->sock)
        return;

    LineReader reader(*p->sock, std::move(p->pendingRx));
    std::string line;
    while (m_running.load() && p->alive && reader.readLine(line))
    {
        p->lastRx.store(nowSeconds());
        if (!HandleLine(*p, line))
            break;
    }
    if (!m_running.load())
    {
        p->shutdown();
        return;
    }
    Remove(p->id, p->alive ? "connection lost" : "disconnected");
}

bool RelayServer::CheckFlood(Participant& p, bool garbage, bool dhRequest,
                             const std::string& text)
{
    const std::uint64_t now = nowSeconds();
    const unsigned window = std::max(1u, m_config.floodWindowSec);
    if (p.floodWindow == 0 || now - p.floodWindow >= window)
    {
        p.floodWindow = now;
        p.floodMessages = 0;
        p.floodRepeats = 0;
        p.floodGarbage = 0;
        p.floodDh = 0;
        p.floodWarned = false;
        p.recentMessages.clear();
    }

    ++p.floodMessages;
    if (garbage)
        ++p.floodGarbage;
    if (dhRequest)
        ++p.floodDh;

    if (!text.empty())
    {
        bool repeat = false;
        for (const auto& old : p.recentMessages)
        {
            if (old == text)
            {
                repeat = true;
                break;
            }
        }
        if (repeat)
            ++p.floodRepeats;
        p.recentMessages.push_back(text);
        if (p.recentMessages.size() > 12)
            p.recentMessages.pop_front();
    }

    if ((m_config.floodMessageLimit > 0 &&
         p.floodMessages > m_config.floodMessageLimit) ||
        (m_config.floodRepeatLimit > 0 &&
         p.floodRepeats > m_config.floodRepeatLimit) ||
        (m_config.floodGarbageLimit > 0 &&
         p.floodGarbage > m_config.floodGarbageLimit) ||
        (m_config.floodDhLimit > 0 && p.floodDh > m_config.floodDhLimit))
    {
        Log("[!] anti-flood: dropping #" + std::to_string(p.id) + " " + p.nick);
        return true;
    }

    if (!p.floodWarned && m_config.floodMessageLimit > 0 &&
        p.floodMessages >= (m_config.floodMessageLimit * 3) / 4)
    {
        p.floodWarned = true;
        const std::string plain = makePlain(
            "SERVER", m_myFp, m_nick,
            "warning: you are sending messages too fast");
        if (p.plain)
            p.sendLine("MSG " + encodePlain(plain));
        else
            p.sendLine("MSG " + makeFrame(p.key, plain));
    }
    return false;
}

bool RelayServer::HandleLine(Participant& p, const std::string& line)
{
    const std::size_t sp = line.find(' ');
    const std::string type = sp == std::string::npos ? line : line.substr(0, sp);
    const std::string payload = sp == std::string::npos ? "" : line.substr(sp + 1);

    if (type == "PING")
    {
        if (CheckFlood(p, false, false, {}))
            return false;
        p.sendLine("PONG " + payload);
        return true;
    }
    if (type == "PONG")
        return true;
    if (type == "REKEY" || type == "REKEY_ACK" || type == "REKEY_DONE")
    {
        if (CheckFlood(p, false, true, {}))
            return false;
        return true;
    }
    if (type == "BYE")
        return false;

    if (type == "NICK")
    {
        std::vector<std::uint8_t> raw;
        if (base64Decode(payload, raw))
        {
            const std::string n(raw.begin(), raw.end());
            if (!isValidNick(n))
            {
                Log("[!] #" + std::to_string(p.id) +
                    " sent an invalid nickname; dropping");
                return false;
            }
            p.nick = n;
            Log("[nick] #" + std::to_string(p.id) + " is now " + n);
            BroadcastRoster();
        }
        return true;
    }

    if (type != "MSG")
    {
        if (CheckFlood(p, true, false, {}))
            return false;
        return true;
    }

    std::string plainText;
    if (p.plain)
    {
        if (!decodePlain(payload, plainText))
        {
            if (CheckFlood(p, true, false, {}))
                return false;
            Log("[!] malformed plaintext message from #" + std::to_string(p.id));
            return true;
        }
    }
    else if (!decryptFrame(payload, p.key, plainText))
    {
        if (CheckFlood(p, true, false, {}))
            return false;
        Log("[!] can't decrypt a message from #" + std::to_string(p.id));
        return true;
    }

    PlainData data;
    if (!parsePlain(plainText, data))
    {
        if (CheckFlood(p, true, false, {}))
            return false;
        return true;
    }

    if (hasForbiddenControlBytes(data.text) ||
        hasForbiddenControlBytes(data.type) ||
        hasForbiddenControlBytes(data.fromFp) ||
        hasForbiddenControlBytes(data.fromNick))
    {
        Log("[!] #" + std::to_string(p.id) +
            " sent forbidden control bytes; dropping");
        return false;
    }

    if (data.type == "CHAT")
    {
        if (CheckFlood(p, false, false, data.text))
            return false;
        if (data.text.size() > kMaxChatBytes)
            return true;
        BroadcastChat(p, data.text);
    }
    else if (data.type == "PING")
    {
        if (CheckFlood(p, false, false, data.text))
            return false;
        const std::string pong = makePlain("PONG", m_myFp, m_nick, data.text);
        if (p.plain)
            p.sendLine("MSG " + encodePlain(pong));
        else
            p.sendLine("MSG " + makeFrame(p.key, pong));
    }
    else if (CheckFlood(p, true, false, {}))
        return false;
    return true;
}

void RelayServer::Remove(int id, const std::string& reason)
{
    std::shared_ptr<Participant> p;
    {
        std::lock_guard<std::mutex> lk(m_partsMutex);
        auto it = m_parts.find(id);
        if (it == m_parts.end())
            return;
        p = it->second;
        m_parts.erase(it);
    }

    p->sendLine("BYE");
    p->shutdown();
    Log("[-] participant #" + std::to_string(id) + " \"" + p->nick + "\" " + reason);
    BroadcastRoster();
}

void RelayServer::JanitorLoop()
{
    while (m_running.load())
    {
        for (int i = 0; i < 5 && m_running.load(); ++i)
            std::this_thread::sleep_for(std::chrono::seconds(1));
        if (!m_running.load())
            break;

        const std::uint64_t now = nowSeconds();
        std::vector<int> dead;
        {
            std::lock_guard<std::mutex> lk(m_partsMutex);
            for (auto& it : m_parts)
            {
                if (now - it.second->lastRx.load() >= kPeerTimeoutSeconds)
                    dead.push_back(it.first);
            }
        }
        for (int id : dead)
            Remove(id, "timed out");
    }
}

} // namespace TriMessage
