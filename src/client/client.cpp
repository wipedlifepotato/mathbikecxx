#include "client.h"

#include "common/frame.h"
#include "common/handshake.h"
#include "common/lines.h"
#include "common/protocol.h"
#include "common/util.h"

#include "alberthofman.h"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <thread>

namespace TriMessage
{

/* ---------- client ---------- */

Client::Client(Config cfg)
    : m_config(std::move(cfg)),
      m_nick(sanitizeNick(m_config.nick))
{
    m_config.nick = m_nick;
    if (m_config.samSession.empty())
    {
        m_config.samSession = "TriMessage-" + m_nick + "-" + randomHex(2);
        SaveConfig();
    }
    m_sessionName = m_config.samSession;

    const std::string& privKey = m_config.privateKey;
    std::string sigType = signatureTypeFromPrivate(privKey);
    if (sigType.empty())
        sigType = m_config.samSignatureType;

    if (privKey.empty())
        m_session = std::make_unique<SAM::StreamSession>(
            m_sessionName, m_config.samHost, m_config.samPort);
    else
        m_session = std::make_unique<SAM::StreamSession>(
            m_sessionName, m_config.samHost, m_config.samPort, privKey,
            SAM_DEFAULT_I2P_OPTIONS, sigType);

    if (!m_session || m_session->isSick())
        throw std::runtime_error("Can't init SAM stream session");

    const SAM::FullDestination& dest = m_session->getMyDestination();
    m_myPub = publicDestinationFromPrivate(dest.priv);

    /*
     * SESSION STATUS returns the private destination.  Split the public part
     * off it.  If that is not possible for a transient session, ask SAM for a
     * fresh keypair and persist it in the config.
     */
    if (m_myPub.empty())
    {
        if (!privKey.empty())
        {
            m_myPub = dest.pub;
            WriteMessage("[!] SAM returned a private destination I cannot split; "
                         "the address printed below may not be usable for /connect");
        }
        else
        {
            auto generated = m_session->destGenerate();
            if (generated.isOk && !generated.value.pub.empty() &&
                !generated.value.priv.empty())
            {
                m_myPub = generated.value.pub;
                m_config.privateKey = generated.value.priv;
                /* DEST GENERATE without SIGNATURE_TYPE returns DSA_SHA1. */
                m_config.samSignatureType = "DSA_SHA1";
                m_config.samSession = m_sessionName + "-" + randomHex(2);
                m_sessionName = m_config.samSession;
                SaveConfig();

                m_session.reset();
                m_session = std::make_unique<SAM::StreamSession>(
                    m_sessionName, m_config.samHost, m_config.samPort,
                    m_config.privateKey, SAM_DEFAULT_I2P_OPTIONS, "DSA_SHA1");
                if (!m_session || m_session->isSick())
                    throw std::runtime_error("Can't init SAM session with generated destination");
            }
            else
            {
                m_myPub = dest.pub;
                WriteMessage("[!] SAM returned a private destination I cannot split; "
                             "the address printed below may not be usable for /connect");
            }
        }
    }

    if (m_myPub.empty())
        throw std::runtime_error("SAM returned an empty destination");
    m_myFp = fingerprintOf(m_myPub);

    WriteMessage("TriMessage is starting...");
    WriteMessage("nick:        " + m_nick);
    WriteMessage("destination: " + m_myPub);
    WriteMessage("fingerprint: " + m_myFp);
    WriteMessage("SAM:         " + m_session->getSAMHost() + ":" +
                 std::to_string(m_session->getSAMPort()));
    WriteMessage("config:      " + m_config.path);

    RegenerateGroup();

    m_acceptThread = std::thread(&Client::AcceptLoop, this);
    m_rekeyThread = std::thread(&Client::RekeyLoop, this);
}

Client::~Client()
{
    m_running.store(false);

    std::vector<std::shared_ptr<Peer>> peers;
    {
        std::lock_guard<std::mutex> lk(m_peersMutex);
        for (auto& it : m_peers)
            peers.push_back(it.second);
        m_peers.clear();
    }
    for (auto& p : peers)
    {
        p->sendLine("BYE");
        p->shutdown();
    }

    if (m_acceptThread.joinable())
        m_acceptThread.detach();
    if (m_rekeyThread.joinable())
        m_rekeyThread.detach();
}

void Client::RegenerateGroup()
{
    WriteMessage("generating DH group (" + std::to_string(m_config.dhBits) + " bits)...");
    m_groupP = DiffiHofman::random_n(m_config.dhBits);
    m_groupG = DiffiHofman::random_n(m_config.groupBits);
    WriteMessage("DH group is ready");
}

bool Client::SaveConfig()
{
    std::string err;
    if (!saveConfig(m_config, err))
    {
        WriteMessage("[!] can't save config: " + err);
        return false;
    }
    return true;
}

void Client::WriteMessage(const std::string& text)
{
    std::lock_guard<std::mutex> lk(m_outMutex);
    std::cout << text << std::endl;
}

void Client::ShutdownNow()
{
    WriteMessage("");
    WriteMessage("shutting down...");

    for (const auto& peer : SnapshotPeers())
    {
        peer->sendLine("BYE");
        peer->shutdown();
    }

    m_running.store(false);
    std::cout.flush();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    std::_Exit(0);
}

std::string Client::Nick()
{
    std::lock_guard<std::mutex> lk(m_nickMutex);
    return m_nick;
}

void Client::SetNick(const std::string& n)
{
    std::lock_guard<std::mutex> lk(m_nickMutex);
    m_nick = sanitizeNick(n);
}

std::string Client::MyPub()
{
    return m_myPub;
}

std::string Client::MyFp()
{
    return m_myFp;
}

int Client::ActivePeer()
{
    return m_activePeer.load();
}

void Client::SetActivePeer(int id)
{
    m_activePeer.store(id);
}

std::vector<std::shared_ptr<Peer>> Client::SnapshotPeers()
{
    std::lock_guard<std::mutex> lk(m_peersMutex);
    std::vector<std::shared_ptr<Peer>> out;
    out.reserve(m_peers.size());
    for (auto& it : m_peers)
        out.push_back(it.second);
    return out;
}

std::shared_ptr<Peer> Client::FindPeerById(int id)
{
    std::lock_guard<std::mutex> lk(m_peersMutex);
    auto it = m_peers.find(id);
    return it == m_peers.end() ? nullptr : it->second;
}

std::shared_ptr<Peer> Client::FindPeer(const std::string& what)
{
    if (what.empty())
        return nullptr;

    try
    {
        const int id = std::stoi(what);
        auto byId = FindPeerById(id);
        if (byId)
            return byId;
    }
    catch (...)
    {
    }

    const std::string needle = lower(what);
    for (const auto& peer : SnapshotPeers())
    {
        if (lower(peer->nickname()) == needle)
            return peer;
        if (lower(peer->fingerprint()).compare(0, needle.size(), needle) == 0)
            return peer;
        if (peer->destination() == what)
            return peer;
    }
    return nullptr;
}

void Client::SetRelayRoster(const std::vector<std::string>& roster)
{
    std::lock_guard<std::mutex> lk(m_rosterMutex);
    m_relayRoster = roster;
}

std::vector<std::string> Client::RelayRoster()
{
    std::lock_guard<std::mutex> lk(m_rosterMutex);
    return m_relayRoster;
}

void Client::SendChatTo(const std::shared_ptr<Peer>& peer, const std::string& text)
{
    if (!peer)
    {
        WriteMessage("no active chat. Use /chat <id> or /connect <destination>");
        return;
    }
    if (text.empty())
    {
        WriteMessage("empty message, not sent");
        return;
    }
    if (text.size() > kMaxChatBytes)
    {
        WriteMessage("message is too big (max " + std::to_string(kMaxChatBytes) + " bytes)");
        return;
    }
    if (!peer->sendEncrypted("CHAT", text))
    {
        WriteMessage("can't send message to #" + std::to_string(peer->id()) +
                     " (connection lost)");
        DropPeer(peer->id(), "connection lost");
        return;
    }
    if (peer->isRelay())
        WriteMessage("[me -> relay] " + text);
    else
        WriteMessage("[me -> " + peer->nickname() + "#" + std::to_string(peer->id()) +
                     "] " + text);
}

void Client::OnChat(Peer& peer, const PlainData& data)
{
    std::string line;
    if (peer.isRelay())
    {
        const std::string fromNick =
            data.fromNick.empty() ? std::string("anonymous") : data.fromNick;
        const std::string fp = data.fromFp.empty() ? std::string("?") : shortFp(data.fromFp);
        line = "[" + fromNick + " " + fp + "] " + data.text;
        peer.addHistory(line);
        WriteMessage(line);
        return;
    }

    line = "[" + peer.nickname() + "#" + std::to_string(peer.id()) + "] " + data.text;
    peer.addHistory(line);
    if (ActivePeer() == peer.id())
        WriteMessage(line);
    else
        WriteMessage("[#" + std::to_string(peer.id()) + " " + peer.nickname() +
                     "] (new message) " + data.text);
}

void Client::PrintPeerHistory(const std::shared_ptr<Peer>& peer)
{
    if (!peer)
        return;
    const auto lines = peer->history();
    if (lines.empty())
    {
        WriteMessage("(no messages with " + peer->nickname() + " yet)");
        return;
    }
    for (const auto& line : lines)
        WriteMessage(line);
}

bool Client::CheckPeerDh(const HsData& hs, bool interactive, std::string& reason)
{
    if (hs.p.empty())
    {
        reason = "peer did not send a DH group";
        return false;
    }

    unsigned pBits = 0;
    unsigned pubBits = 0;
    try
    {
        const mpz_class p(hs.p);
        pBits = static_cast<unsigned>(mpz_sizeinbase(p.get_mpz_t(), 2));
        if (!hs.dhPub.empty())
        {
            const mpz_class pub(hs.dhPub);
            pubBits = static_cast<unsigned>(mpz_sizeinbase(pub.get_mpz_t(), 2));
        }
    }
    catch (...)
    {
        reason = "peer sent an invalid DH key";
        return false;
    }

    const unsigned biggest = std::max(pBits, pubBits);
    if (m_config.maxPeerDhBits == 0 || biggest <= m_config.maxPeerDhBits)
        return true;

    if (m_config.allowHugeDh)
        return true;

    std::ostringstream os;
    os << "peer #" << shortFp(hs.fp) << " offers a " << biggest
       << "-bit DH key (your warning limit is " << m_config.maxPeerDhBits
       << "). A very large key can take a long time to verify. Continue?";
    if (!interactive)
    {
        reason = "peer DH key is too large (" + std::to_string(biggest) +
                 " bits); set allow_huge_dh = true in the config to permit it";
        return false;
    }
    if (!askYesNo(os.str(), false))
    {
        reason = "you declined the large DH key";
        return false;
    }
    return true;
}

/* ---------- networking ---------- */

void Client::AcceptLoop()
{
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

        if (!HandleIncoming(std::move(result.value)) && m_running.load())
            std::this_thread::sleep_for(std::chrono::milliseconds(300));
    }
}

bool Client::HandleIncoming(std::unique_ptr<SAM::I2pSocket> sock)
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
                    WriteMessage("[!] SAM accept failed: " + line);
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
                WriteMessage("[!] unexpected first line on accept (not a destination)");
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
        if (cli.relayVersion != kRelayDirect)
        {
            sendLine("HELLO_REJECT direct peers only");
            return false;
        }
        if (cli.fp != fingerprintOf(cli.dest))
        {
            WriteMessage("[!] incoming HELLO has a bad fingerprint");
            return false;
        }
        if (!samDest.empty() && samDest != cli.dest)
        {
            WriteMessage("[!] incoming HELLO destination does not match the SAM peer");
            return false;
        }
        if (cli.dest == MyPub())
        {
            sendLine("HELLO_REJECT own destination");
            WriteMessage("[!] rejected a connection from my own destination; "
                         "the relay and the client must use different configs");
            return false;
        }

        std::string reason;
        if (!CheckPeerDh(cli, false, reason))
        {
            sendLine("HELLO_REJECT " + reason);
            WriteMessage("[!] rejected incoming peer: " + reason);
            return false;
        }

        DiffiHofman dh(mpz_class(cli.p), mpz_class(cli.g));
        const mpz_class myDhPub = dh.getPublicKey(m_config.secretBits);

        HsData srv;
        srv.nick = Nick();
        srv.dest = MyPub();
        srv.fp = MyFp();
        srv.p = cli.p;
        srv.g = cli.g;
        srv.dhPub = myDhPub.get_str();
        srv.challenge = randomHex(16);
        srv.relayVersion = kRelayDirect;
        srv.role = "server";

        if (!sendLine("HELLO_ACK " + encodeHs(srv)))
            return false;

        const KeyMaterial key = deriveKey(dh.getSharedKey(mpz_class(cli.dhPub)));
        const std::string transcript = makeTranscript(cli, srv);

        if (!reader.readLine(line))
            return false;
        const std::size_t sp2 = line.find(' ');
        const std::string type2 = sp2 == std::string::npos ? line : line.substr(0, sp2);
        const std::string payload2 = sp2 == std::string::npos ? "" : line.substr(sp2 + 1);
        if (type2 != "AUTH")
            return false;

        const std::string expected = makeProof(key, transcript, "client");
        if (!constantTimeEquals(payload2, expected))
        {
            sendLine("AUTH_FAIL");
            WriteMessage("[!] incoming HELLO failed authentication");
            return false;
        }

        if (!sendLine("AUTH " + makeProof(key, transcript, "server")))
            return false;

        if (!reader.readLine(line))
            return false;
        if (line.find("AUTH_OK") != 0)
            return false;

        if (!samDest.empty())
            cli.dest = samDest;

        RegisterPeer(std::move(sock), cli, cli.p, cli.g, key,
                     false, kRelayDirect, false, reader.takeBuffer());
        return true;
    }
    catch (const std::exception& e)
    {
        WriteMessage(std::string("[!] incoming handshake failed: ") + e.what());
        return false;
    }
}

std::shared_ptr<Peer> Client::ConnectTo(const std::string& destination)
{
    const std::string target = normaliseDestination(destination);
    if (target.empty())
    {
        WriteMessage("[!] /connect expects a full I2P destination (base64), "
                     "not a username or addressbook name");
        return nullptr;
    }
    if (target == MyPub())
    {
        WriteMessage("[!] this is my own destination. A relay and a client must "
                     "use different configs with different private_key values");
        return nullptr;
    }

    auto result = m_session->connect(target, false);
    if (!result.isOk || !result.value)
    {
        WriteMessage("[!] SAM can't connect to destination fp=" +
                     shortFp(fingerprintOf(target)));
        return nullptr;
    }
    std::unique_ptr<SAM::I2pSocket> sock = std::move(result.value);

    auto sendLine = [&sock](const std::string& line) {
        sock->write(line + "\n");
        return sock->isOk();
    };

    try
    {
        LineReader reader(*sock);

        DiffiHofman dh(m_groupP, m_groupG);
        const mpz_class myDhPub = dh.getPublicKey(m_config.secretBits);

        HsData cli;
        cli.nick = Nick();
        cli.dest = MyPub();
        cli.fp = MyFp();
        cli.p = m_groupP.get_str();
        cli.g = m_groupG.get_str();
        cli.dhPub = myDhPub.get_str();
        cli.challenge = randomHex(16);
        cli.relayVersion = kRelayDirect;
        cli.role = "client";

        if (!sendLine("HELLO " + encodeHs(cli)))
            return nullptr;

        std::string line;
        if (!reader.readLine(line))
            return nullptr;

        if (line.find(' ') == std::string::npos && looksLikeI2pDestination(line))
        {
            if (!reader.readLine(line))
                return nullptr;
        }

        const std::size_t sp = line.find(' ');
        const std::string type = sp == std::string::npos ? line : line.substr(0, sp);
        const std::string payload = sp == std::string::npos ? "" : line.substr(sp + 1);
        if (type == "HELLO_REJECT")
        {
            WriteMessage("[!] peer rejected the connection: " + payload);
            return nullptr;
        }
        if (type != "HELLO_ACK")
            return nullptr;

        HsData srv;
        if (!decodeHs(payload, srv))
            return nullptr;
        if (srv.fp != fingerprintOf(srv.dest))
            return nullptr;

        const bool isRelay = srv.relayVersion != kRelayDirect;
        const std::string transcript = makeTranscript(cli, srv);

        std::string passwordProof;
        if (isRelay && srv.passwordRequired)
        {
            std::string password = m_config.relayPassword;
            if (password.empty())
            {
                if (!askPassword("relay " + shortFp(srv.fp) + " password: ", password) ||
                    password.empty())
                {
                    sendLine("BYE");
                    WriteMessage("[!] this relay requires a password");
                    return nullptr;
                }
            }
            passwordProof = makePasswordProof(password, transcript);
        }

        if (srv.relayVersion == kRelayPlain)
        {
            if (m_config.relayAskPlain)
            {
                const bool ok = askYesNo(
                    "server " + shortFp(srv.fp) + " is an UNENCRYPTED relay "
                    "(protocol version 3). Anything you send can be read by the "
                    "relay and by anybody who can see its traffic. Connect anyway?",
                    false);
                if (!ok)
                {
                    sendLine("BYE");
                    WriteMessage("connection cancelled");
                    return nullptr;
                }
            }

            if (!sendLine(srv.passwordRequired ? "AUTH " + passwordProof : "AUTH_OK"))
                return nullptr;

            if (!reader.readLine(line))
                return nullptr;
            if (line.rfind("AUTH_FAIL", 0) == 0)
            {
                WriteMessage(std::string("[!] relay refused the connection") +
                             (srv.passwordRequired ? ": wrong password" : ""));
                return nullptr;
            }
            if (line != "AUTH_OK")
            {
                WriteMessage("[!] relay did not confirm the connection");
                return nullptr;
            }

            return RegisterPeer(std::move(sock), srv, "", "", KeyMaterial{},
                                true, kRelayPlain, true, reader.takeBuffer());
        }

        if (mpz_class(srv.p) != m_groupP || mpz_class(srv.g) != m_groupG)
        {
            WriteMessage("[!] peer changed the DH group");
            sendLine("BYE");
            return nullptr;
        }

        std::string reason;
        if (!CheckPeerDh(srv, true, reason))
        {
            WriteMessage("[!] " + reason);
            sendLine("BYE");
            return nullptr;
        }

        const KeyMaterial key = deriveKey(dh.getSharedKey(mpz_class(srv.dhPub)));

        std::string auth = "AUTH " + makeProof(key, transcript, "client");
        if (srv.passwordRequired)
            auth += " " + passwordProof;

        if (!sendLine(auth))
            return nullptr;

        if (!reader.readLine(line))
            return nullptr;
        const std::size_t sp2 = line.find(' ');
        const std::string type2 = sp2 == std::string::npos ? line : line.substr(0, sp2);
        const std::string payload2 = sp2 == std::string::npos ? "" : line.substr(sp2 + 1);
        if (type2 == "AUTH_FAIL")
        {
            WriteMessage(std::string("[!] relay refused the connection") +
                         (srv.passwordRequired ? ": wrong password" : ""));
            return nullptr;
        }
        if (type2 != "AUTH" ||
            !constantTimeEquals(payload2, makeProof(key, transcript, "server")))
        {
            WriteMessage("[!] server failed authentication");
            return nullptr;
        }

        if (!sendLine("AUTH_OK"))
            return nullptr;

        return RegisterPeer(std::move(sock), srv, srv.p, srv.g, key,
                            isRelay, srv.relayVersion, false,
                            reader.takeBuffer());
    }
    catch (const std::exception& e)
    {
        WriteMessage(std::string("[!] outgoing handshake failed: ") + e.what());
        return nullptr;
    }
}

std::shared_ptr<Peer> Client::RegisterPeer(std::unique_ptr<SAM::I2pSocket> sock,
                                           const HsData& remote,
                                           const std::string& groupP,
                                           const std::string& groupG,
                                           const KeyMaterial& key,
                                           bool relay,
                                           std::uint8_t relayVersion,
                                           bool plain,
                                           std::string pendingRx)
{
    if (remote.dest == MyPub())
    {
        WriteMessage("[!] refusing to register my own destination as a peer");
        sock.reset();
        return nullptr;
    }

    for (const auto& old : SnapshotPeers())
    {
        if (old->destination() == remote.dest)
        {
            WriteMessage("[!] already connected to " + remote.nick +
                         " (fingerprint " + shortFp(remote.fp) + ")");
            sock.reset();
            return nullptr;
        }
    }

    const int id = m_nextPeerId.fetch_add(1);
    auto peer = std::make_shared<Peer>(id,
                                       std::move(sock),
                                       sanitizeNick(remote.nick),
                                       remote.dest,
                                       remote.fp,
                                       groupP,
                                       groupG,
                                       key,
                                       Nick(),
                                       MyFp(),
                                       relay,
                                       relayVersion,
                                       plain,
                                       m_config.rekeySecretBits);

    {
        std::lock_guard<std::mutex> lk(m_peersMutex);
        m_peers[id] = peer;
    }

    if (relay)
    {
        WriteMessage("[+] relay #" + std::to_string(id) + " \"" +
                     peer->nickname() + "\" connected, version " +
                     std::to_string(relayVersion) +
                     (plain ? " (NO ENCRYPTION)" : " (encrypted)"));
        WriteMessage("[+] relay fingerprint " + shortFp(peer->fingerprint()));
    }
    else
    {
        WriteMessage("[+] user #" + std::to_string(id) + " \"" + peer->nickname() +
                     "\" connected, fingerprint " + shortFp(peer->fingerprint()));
    }

    std::thread(&Client::PeerLoop, this, peer, std::move(pendingRx)).detach();
    return peer;
}

bool Client::DropPeer(int id, const std::string& reason)
{
    std::shared_ptr<Peer> peer;
    {
        std::lock_guard<std::mutex> lk(m_peersMutex);
        auto it = m_peers.find(id);
        if (it == m_peers.end())
            return false;
        peer = it->second;
        m_peers.erase(it);
    }

    peer->sendLine("BYE");
    peer->shutdown();
    if (ActivePeer() == id)
        SetActivePeer(-1);

    if (peer->isRelay())
        SetRelayRoster({});

    WriteMessage("[-] " + std::string(peer->isRelay() ? "relay" : "user") +
                 " #" + std::to_string(id) + " \"" + peer->nickname() +
                 "\" " + reason);
    return true;
}

void Client::PeerLoop(std::shared_ptr<Peer> peer, std::string pendingRx)
{
    LineReader reader(*peer->socket(), std::move(pendingRx));
    std::string line;
    while (m_running.load() && peer->alive() && reader.readLine(line))
    {
        peer->touchRx();
        if (!HandlePeerLine(*peer, line))
            break;
    }
    if (!m_running.load())
    {
        peer->shutdown();
        return;
    }
    DropPeer(peer->id(), peer->alive() ? "connection lost" : "disconnected");
}

bool Client::HandlePeerLine(Peer& peer, const std::string& line)
{
    const std::size_t sp = line.find(' ');
    const std::string type = sp == std::string::npos ? line : line.substr(0, sp);
    const std::string payload = sp == std::string::npos ? "" : line.substr(sp + 1);

    if (type == "MSG")
    {
        std::string plain;
        if (!peer.decrypt(payload, plain))
        {
            WriteMessage("[!] can't decrypt message from #" + std::to_string(peer.id()));
            return true;
        }

        PlainData data;
        if (!parsePlain(plain, data))
            return true;

        if (!peer.isRelay() && data.fromFp != peer.fingerprint())
        {
            WriteMessage("[!] message from #" + std::to_string(peer.id()) +
                         " has a wrong sender fingerprint");
            return true;
        }

        if (data.type == "CHAT")
        {
            OnChat(peer, data);
        }
        else if (data.type == "PING")
        {
            peer.sendEncrypted("PONG", data.text);
        }
        else if (data.type == "USERS" && peer.isRelay())
        {
            std::vector<std::string> roster;
            if (!data.text.empty())
            {
                for (const auto& entry : splitChar(data.text, ';'))
                {
                    const auto parts = splitChar(entry, ':');
                    if (parts.size() != 3)
                        continue;
                    roster.push_back(parts[1] + " #" + parts[0] + " fp=" +
                                     shortFp(parts[2]));
                }
            }
            SetRelayRoster(roster);
            WriteMessage("[relay] participants: " +
                         std::to_string(roster.size()));
            for (const auto& r : roster)
                WriteMessage("  " + r);
        }
        else if (data.type == "SERVER" && peer.isRelay())
        {
            WriteMessage("[relay] " + data.text);
        }
        return true;
    }

    if (type == "PING")
    {
        peer.sendLine("PONG " + payload);
        return true;
    }

    if (type == "PONG")
    {
        const long ms = peer.handlePong(payload);
        if (ms >= 0)
            WriteMessage("[pong] #" + std::to_string(peer.id()) + " " +
                         peer.nickname() + ": " + std::to_string(ms) + " ms");
        return true;
    }

    if (type == "NICK")
    {
        std::vector<std::uint8_t> raw;
        if (base64Decode(payload, raw))
        {
            const std::string n(raw.begin(), raw.end());
            peer.setNickname(n);
            WriteMessage("[nick] #" + std::to_string(peer.id()) + " is now " +
                         peer.nickname());
        }
        return true;
    }

    if (type == "REKEY")
    {
        if (peer.handleRekey(payload))
            WriteMessage("[rekey] key refresh requested by #" +
                         std::to_string(peer.id()) + " " + peer.nickname());
        return true;
    }

    if (type == "REKEY_ACK")
    {
        if (peer.handleRekeyAck(payload))
            WriteMessage("[rekey] key refreshed with #" + std::to_string(peer.id()) +
                         " " + peer.nickname());
        return true;
    }

    if (type == "REKEY_DONE")
    {
        if (peer.handleRekeyDone(payload))
            WriteMessage("[rekey] key refresh confirmed by #" +
                         std::to_string(peer.id()) + " " + peer.nickname());
        return true;
    }

    if (type == "BYE" || type == "AUTH_FAIL")
        return false;

    return true;
}

void Client::RekeyLoop()
{
    while (m_running.load())
    {
        for (int i = 0; i < 5 && m_running.load(); ++i)
            std::this_thread::sleep_for(std::chrono::seconds(1));
        if (!m_running.load())
            break;

        const std::uint64_t now = nowSeconds();
        const std::string myFp = MyFp();
        for (const auto& peer : SnapshotPeers())
        {
            if (!peer->alive())
                continue;

            const std::uint64_t silent = now - peer->lastRxSec();
            if (silent >= kPeerTimeoutSeconds)
            {
                DropPeer(peer->id(), "connection timed out");
                continue;
            }
            if (silent >= kHeartbeatSeconds &&
                now - peer->lastPingSentSec() >= kHeartbeatSeconds)
            {
                peer->markPingSent();
                if (!peer->sendPing())
                {
                    DropPeer(peer->id(), "connection lost");
                    continue;
                }
            }

            if (!peer->canRekey())
                continue;
            if (now - peer->lastRekeySec() < peer->rekeyIntervalSec())
                continue;

            peer->resetRekeyClock();

            if (myFp < peer->fingerprint())
            {
                if (peer->beginRekey())
                    WriteMessage("[rekey] starting key refresh with #" +
                                 std::to_string(peer->id()) + " " + peer->nickname());
            }
        }
    }
}

/* ---------- commands ---------- */

bool Client::CmdHelp(const ParamsT&)
{
    WriteMessage("/help                 - this help");
    WriteMessage("/getMyPubKey          - print my I2P destination and fingerprint");
    WriteMessage("/connect <destination> - connect using a full I2P destination");
    WriteMessage("/users                - list connected users");
    WriteMessage("/chat <id|nick>       - select a user and show its buffer");
    WriteMessage("/msg [id|nick] <text> - send an encrypted message");
    WriteMessage("/ping [id|nick|destination] - round-trip time (no args = all)");
    WriteMessage("/deluser <id|nick>    - drop a user and close the stream");
    WriteMessage("/nick <name>          - change my nickname");
    WriteMessage("/rekey [id|nick]      - force a new DH exchange");
    WriteMessage("/settings [key value] - show or change persistent settings");
    WriteMessage("/status               - show local node state");
    WriteMessage("/quit                 - exit");
    WriteMessage("");
    WriteMessage("A line without '/' is sent to the active chat.");
    return true;
}

bool Client::CmdGetMyPubKey(const ParamsT&)
{
    WriteMessage("nick:        " + Nick());
    WriteMessage("destination: " + MyPub());
    WriteMessage("fingerprint: " + MyFp());
    return true;
}

bool Client::CmdStatus(const ParamsT&)
{
    const auto peers = SnapshotPeers();
    WriteMessage("nick:        " + Nick());
    WriteMessage("fingerprint: " + MyFp());
    WriteMessage("DH bits:     " + std::to_string(m_config.dhBits) +
                 " (secret " + std::to_string(m_config.secretBits) + ")");
    WriteMessage("config:      " + m_config.path);
    WriteMessage("peers:       " + std::to_string(peers.size()));
    WriteMessage("active:      " + std::to_string(ActivePeer()));
    const auto roster = RelayRoster();
    if (!roster.empty())
    {
        WriteMessage("relay roster:");
        for (const auto& r : roster)
            WriteMessage("  " + r);
    }
    for (const auto& p : peers)
    {
        const long ms = p->lastPingMs();
        WriteMessage("  #" + std::to_string(p->id()) + " " + p->nickname() +
                     (p->isRelay() ? " (relay v" + std::to_string(p->relayVersion()) + ")" : "") +
                     " fp=" + shortFp(p->fingerprint()) +
                     (ms >= 0 ? " ping=" + std::to_string(ms) + "ms" : " ping=n/a"));
    }
    return true;
}

bool Client::CmdNick(const ParamsT& params)
{
    if (params.empty())
    {
        WriteMessage("usage: /nick <name>");
        return true;
    }
    const std::string n = sanitizeNick(params[0]);
    SetNick(n);
    m_config.nick = n;
    SaveConfig();

    for (const auto& p : SnapshotPeers())
    {
        p->setMyNickname(n);
        p->sendLine("NICK " + base64Encode(n));
    }
    WriteMessage("my nickname is now " + n);
    return true;
}

bool Client::CmdQuit(const ParamsT&)
{
    WriteMessage("bye");
    m_running.store(false);
    return false;
}

bool Client::CmdSettings(const ParamsT& params)
{
    if (params.empty())
    {
        WriteMessage("settings (" + m_config.path + "):");
        WriteMessage("  nick = " + m_config.nick);
        WriteMessage("  private_key = " +
                     std::string(m_config.privateKey.empty() ? "(not set)" : "(set, hidden)"));
        WriteMessage("  sam_host = " + m_config.samHost);
        WriteMessage("  sam_port = " + std::to_string(m_config.samPort));
        WriteMessage("  sam_session = " + m_config.samSession);
        WriteMessage("  sam_signature_type = " + m_config.samSignatureType);
        WriteMessage("  dh_bits = " + std::to_string(m_config.dhBits));
        WriteMessage("  group_bits = " + std::to_string(m_config.groupBits));
        WriteMessage("  secret_bits = " + std::to_string(m_config.secretBits));
        WriteMessage("  rekey_secret_bits = " + std::to_string(m_config.rekeySecretBits));
        WriteMessage("  max_peer_dh_bits = " + std::to_string(m_config.maxPeerDhBits));
        WriteMessage("  allow_huge_dh = " + std::string(m_config.allowHugeDh ? "true" : "false"));
        WriteMessage("  server_mode = " + std::string(m_config.serverMode ? "true" : "false"));
        WriteMessage("  daemon_mode = " + std::string(m_config.daemonMode ? "true" : "false"));
        WriteMessage("  relay_version = " + std::to_string(m_config.relayVersion));
        WriteMessage("  relay_limit = " + std::to_string(m_config.relayLimit));
        WriteMessage("  relay_anonymous = " +
                     std::string(m_config.relayAnonymous ? "true" : "false"));
        WriteMessage("  relay_ask_plain = " +
                     std::string(m_config.relayAskPlain ? "true" : "false"));
        WriteMessage("  relay_password = " +
                     std::string(m_config.relayPassword.empty() ? "(not set)" : "(set, hidden)"));
        WriteMessage("usage: /settings <key> <value>");
        return true;
    }

    if (params.size() < 2)
    {
        WriteMessage("usage: /settings <key> <value>");
        return true;
    }

    const std::string key = lower(params[0]);
    const std::string value = params[1];

    auto parseBoolValue = [](const std::string& v, bool& out) {
        const std::string x = lower(trimCopy(v));
        if (x == "1" || x == "true" || x == "yes" || x == "on")
        {
            out = true;
            return true;
        }
        if (x == "0" || x == "false" || x == "no" || x == "off")
        {
            out = false;
            return true;
        }
        return false;
    };
    auto parseUnsigned = [](const std::string& v, unsigned& out, unsigned lo, unsigned hi) {
        try
        {
            const unsigned long x = std::stoul(trimCopy(v));
            if (x < lo || x > hi)
                return false;
            out = static_cast<unsigned>(x);
            return true;
        }
        catch (...)
        {
            return false;
        }
    };

    auto bad = [&](const std::string& what) {
        WriteMessage("[!] invalid value for " + key + ": " + value + " (" + what + ")");
        return true;
    };

    if (key == "nick")
    {
        return CmdNick({value});
    }
    if (key == "private_key")
    {
        WriteMessage("[!] private_key is managed by the program; delete the config "
                     "to generate a new one");
        return true;
    }
    if (key == "sam_host")
    {
        m_config.samHost = value;
        SaveConfig();
        WriteMessage("sam_host saved; restart to apply");
        return true;
    }
    if (key == "sam_port")
    {
        unsigned v = 0;
        if (!parseUnsigned(value, v, 1, 65535))
            return bad("1..65535");
        m_config.samPort = static_cast<std::uint16_t>(v);
        SaveConfig();
        WriteMessage("sam_port saved; restart to apply");
        return true;
    }
    if (key == "sam_session")
    {
        m_config.samSession = value;
        SaveConfig();
        WriteMessage("sam_session saved; restart to apply");
        return true;
    }
    if (key == "sam_signature_type")
    {
        m_config.samSignatureType = value;
        SaveConfig();
        WriteMessage("sam_signature_type saved; restart to apply");
        return true;
    }
    if (key == "dh_bits")
    {
        unsigned v = 0;
        if (!parseUnsigned(value, v, 64, 65536))
            return bad("64..65536");
        m_config.dhBits = v;
        SaveConfig();
        RegenerateGroup();
        return true;
    }
    if (key == "group_bits")
    {
        unsigned v = 0;
        if (!parseUnsigned(value, v, 16, 4096))
            return bad("16..4096");
        m_config.groupBits = v;
        SaveConfig();
        RegenerateGroup();
        return true;
    }
    if (key == "secret_bits")
    {
        unsigned v = 0;
        if (!parseUnsigned(value, v, 64, 65536))
            return bad("64..65536");
        m_config.secretBits = v;
        SaveConfig();
        return true;
    }
    if (key == "rekey_secret_bits")
    {
        unsigned v = 0;
        if (!parseUnsigned(value, v, 64, 65536))
            return bad("64..65536");
        m_config.rekeySecretBits = v;
        SaveConfig();
        return true;
    }
    if (key == "max_peer_dh_bits")
    {
        unsigned v = 0;
        if (!parseUnsigned(value, v, 0, 65536))
            return bad("0..65536");
        m_config.maxPeerDhBits = v;
        SaveConfig();
        return true;
    }
    if (key == "allow_huge_dh" || key == "server_mode" || key == "daemon_mode" ||
        key == "relay_anonymous" || key == "relay_ask_plain")
    {
        bool v = false;
        if (!parseBoolValue(value, v))
            return bad("true/false");
        if (key == "allow_huge_dh")
            m_config.allowHugeDh = v;
        else if (key == "server_mode")
            m_config.serverMode = v;
        else if (key == "daemon_mode")
            m_config.daemonMode = v;
        else if (key == "relay_anonymous")
            m_config.relayAnonymous = v;
        else
            m_config.relayAskPlain = v;
        SaveConfig();
        if (key != "allow_huge_dh")
            WriteMessage(key + " saved; restart to apply");
        return true;
    }
    if (key == "relay_password")
    {
        m_config.relayPassword = (value == "-") ? std::string() : value;
        SaveConfig();
        WriteMessage("relay_password saved; restart the relay / reconnect to apply");
        return true;
    }
    if (key == "relay_version")
    {
        unsigned v = 0;
        if (!parseUnsigned(value, v, 2, 3))
            return bad("2 or 3");
        m_config.relayVersion = v;
        SaveConfig();
        WriteMessage("relay_version saved; restart the relay to apply");
        return true;
    }
    if (key == "relay_limit")
    {
        unsigned v = 0;
        if (!parseUnsigned(value, v, 1, 100000))
            return bad("1..100000");
        m_config.relayLimit = v;
        SaveConfig();
        WriteMessage("relay_limit saved; restart the relay to apply");
        return true;
    }

    WriteMessage("[!] unknown setting: " + key);
    WriteMessage("known: nick sam_host sam_port sam_session sam_signature_type "
                 "dh_bits group_bits secret_bits rekey_secret_bits max_peer_dh_bits "
                 "allow_huge_dh server_mode daemon_mode relay_version relay_limit "
                 "relay_anonymous relay_ask_plain relay_password");
    return true;
}

/* ---------- commands: chat / network ---------- */

bool Client::CmdConnect(const ParamsT& params)
{
    if (params.empty())
    {
        WriteMessage("usage: /connect <destination>");
        return true;
    }
    WriteMessage("connecting (this can take a while)...");
    auto peer = ConnectTo(params[0]);
    if (!peer)
    {
        WriteMessage("connect failed");
        return true;
    }
    SetActivePeer(peer->id());
    WriteMessage("active chat is now #" + std::to_string(peer->id()) + " " +
                 peer->nickname());
    PrintPeerHistory(peer);
    return true;
}

bool Client::CmdPing(const ParamsT& params)
{
    if (params.empty())
    {
        const auto peers = SnapshotPeers();
        if (peers.empty())
        {
            WriteMessage("no connected users");
            return true;
        }
        for (const auto& peer : peers)
        {
            peer->sendPing();
            WriteMessage("ping -> #" + std::to_string(peer->id()) + " " +
                         peer->nickname());
        }
        return true;
    }

    auto peer = FindPeer(params[0]);
    if (!peer)
    {
        WriteMessage("not connected, trying to connect...");
        peer = ConnectTo(params[0]);
        if (!peer)
        {
            WriteMessage("ping failed: can't connect");
            return true;
        }
        SetActivePeer(peer->id());
    }
    peer->sendPing();
    WriteMessage("ping -> #" + std::to_string(peer->id()) + " " + peer->nickname());
    return true;
}

bool Client::CmdUsers(const ParamsT&)
{
    const auto peers = SnapshotPeers();
    const auto roster = RelayRoster();
    if (!roster.empty())
    {
        WriteMessage("relay participants:");
        for (const auto& r : roster)
            WriteMessage("  " + r);
        WriteMessage("connected relays:");
    }
    if (peers.empty())
    {
        WriteMessage("no connected users");
        return true;
    }

    for (const auto& peer : peers)
    {
        const long ms = peer->lastPingMs();
        std::ostringstream line;
        line << (ActivePeer() == peer->id() ? "*" : " ")
             << " #" << peer->id()
             << " " << peer->nickname()
             << (peer->isRelay() ? " (relay v" + std::to_string(peer->relayVersion()) + ")" : "")
             << " fp=" << shortFp(peer->fingerprint())
             << " ping=" << (ms >= 0 ? std::to_string(ms) + "ms" : std::string("n/a"));
        WriteMessage(line.str());
    }
    return true;
}

bool Client::CmdChat(const ParamsT& params)
{
    if (params.empty())
    {
        WriteMessage("usage: /chat <id|nick>");
        return true;
    }
    auto peer = FindPeer(params[0]);
    if (!peer)
    {
        WriteMessage("no such user: " + params[0]);
        return true;
    }
    SetActivePeer(peer->id());
    WriteMessage("chat with #" + std::to_string(peer->id()) + " " + peer->nickname());
    PrintPeerHistory(peer);
    return true;
}

bool Client::CmdMsg(const ParamsT& params)
{
    if (params.empty())
    {
        WriteMessage("usage: /msg [id|nick] <text>");
        return true;
    }

    std::shared_ptr<Peer> peer;
    std::size_t textFrom = 0;

    if (params.size() >= 2)
    {
        peer = FindPeer(params[0]);
        if (peer)
            textFrom = 1;
    }
    if (!peer)
        peer = FindPeerById(ActivePeer());
    if (!peer)
    {
        WriteMessage("no active chat. Use /chat <id>, /connect <dest> or /msg <id> <text>");
        return true;
    }

    SendChatTo(peer, joinFrom(params, textFrom));
    return true;
}

bool Client::CmdDelUser(const ParamsT& params)
{
    if (params.empty())
    {
        WriteMessage("usage: /deluser <id|nick>");
        return true;
    }
    auto peer = FindPeer(params[0]);
    if (!peer)
    {
        WriteMessage("no such user: " + params[0]);
        return true;
    }
    DropPeer(peer->id(), "removed by /deluser");
    return true;
}

bool Client::CmdRekey(const ParamsT& params)
{
    std::vector<std::shared_ptr<Peer>> peers;
    if (params.empty())
        peers = SnapshotPeers();
    else
    {
        auto peer = FindPeer(params[0]);
        if (!peer)
        {
            WriteMessage("no such user: " + params[0]);
            return true;
        }
        peers.push_back(peer);
    }

    if (peers.empty())
    {
        WriteMessage("no connected users");
        return true;
    }

    for (const auto& peer : peers)
    {
        if (!peer->canRekey())
        {
            WriteMessage("[rekey] #" + std::to_string(peer->id()) + " " +
                         peer->nickname() + " is a relay or plaintext peer; "
                         "rekey is not available");
            continue;
        }
        if (peer->beginRekey())
            WriteMessage("[rekey] requested with #" + std::to_string(peer->id()) +
                         " " + peer->nickname());
        else
            WriteMessage("[rekey] refresh with #" + std::to_string(peer->id()) +
                         " is already in progress");
    }
    return true;
}

CommandsT commands
{
    {"help", [](Client& c, ParamsT p) { return c.CmdHelp(p); }},
    {"getmypubkey", [](Client& c, ParamsT p) { return c.CmdGetMyPubKey(p); }},
    {"mykey", [](Client& c, ParamsT p) { return c.CmdGetMyPubKey(p); }},
    {"connect", [](Client& c, ParamsT p) { return c.CmdConnect(p); }},
    {"ping", [](Client& c, ParamsT p) { return c.CmdPing(p); }},
    {"users", [](Client& c, ParamsT p) { return c.CmdUsers(p); }},
    {"list", [](Client& c, ParamsT p) { return c.CmdUsers(p); }},
    {"chat", [](Client& c, ParamsT p) { return c.CmdChat(p); }},
    {"msg", [](Client& c, ParamsT p) { return c.CmdMsg(p); }},
    {"deluser", [](Client& c, ParamsT p) { return c.CmdDelUser(p); }},
    {"del", [](Client& c, ParamsT p) { return c.CmdDelUser(p); }},
    {"kick", [](Client& c, ParamsT p) { return c.CmdDelUser(p); }},
    {"removeuser", [](Client& c, ParamsT p) { return c.CmdDelUser(p); }},
    {"nick", [](Client& c, ParamsT p) { return c.CmdNick(p); }},
    {"rekey", [](Client& c, ParamsT p) { return c.CmdRekey(p); }},
    {"settings", [](Client& c, ParamsT p) { return c.CmdSettings(p); }},
    {"set", [](Client& c, ParamsT p) { return c.CmdSettings(p); }},
    {"status", [](Client& c, ParamsT p) { return c.CmdStatus(p); }},
    {"quit", [](Client& c, ParamsT p) { return c.CmdQuit(p); }},
    {"exit", [](Client& c, ParamsT p) { return c.CmdQuit(p); }},
    {"q", [](Client& c, ParamsT p) { return c.CmdQuit(p); }}
};

void Client::Run()
{
    WriteMessage("");
    WriteMessage("TriMessage is listening and can connect at the same time.");
    WriteMessage("Type /help for commands.");

    while (m_running.load())
    {
        {
            std::lock_guard<std::mutex> lk(m_outMutex);
            std::cout << "> " << std::flush;
        }

        std::string line;
        if (!std::getline(std::cin, line))
            break;
        if (line.empty())
            continue;

        if (line[0] != '/')
        {
            auto peer = FindPeerById(ActivePeer());
            if (!peer)
                WriteMessage("no active chat. Use /chat <id> or /connect <destination>");
            else
                SendChatTo(peer, sanitizeText(line));
            continue;
        }

        ParamsT params = splitArgs(line.substr(1));
        if (params.empty())
            continue;

        const std::string name = lower(params[0]);
        params.erase(params.begin());

        auto it = commands.find(name);
        if (it == commands.end())
        {
            WriteMessage("unknown command: /" + name + " (try /help)");
            continue;
        }
        if (!it->second(*this, params))
            break;
    }

    m_running.store(false);
}

} // namespace TriMessage
