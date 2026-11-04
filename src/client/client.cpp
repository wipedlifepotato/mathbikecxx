#include "client.h"

#include "common/frame.h"
#include "common/handshake.h"
#include "common/hash.h"
#include "common/lines.h"
#include "common/platform.h"
#include "common/protocol.h"
#include "common/util.h"

#include "alberthofman.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <set>
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
    setColorEnabled(m_config.colors);
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

    std::vector<std::shared_ptr<PendingPeer>> pending;
    {
        std::lock_guard<std::mutex> lk(m_pendingMutex);
        for (auto& it : m_pending)
            pending.push_back(it.second);
        m_pending.clear();
    }
    for (auto& p : pending)
    {
        if (p && p->sock)
        {
            p->sock->write("BYE\n");
            p->sock->close();
        }
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

    {
        std::lock_guard<std::mutex> lk(m_pendingMutex);
        for (auto& it : m_pending)
        {
            if (it.second && it.second->sock)
            {
                it.second->sock->write("BYE\n");
                it.second->sock->close();
            }
        }
        m_pending.clear();
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
        line = "[" + colorNick(fromNick) + " " +
               colorText(fp, "2") + "] " + data.text;
        peer.addHistory(line);
        WriteMessage(line);
        return;
    }

    line = "[" + colorNick(peer.nickname()) + "#" + std::to_string(peer.id()) +
           "] " + data.text;
    peer.addHistory(line);
    if (ActivePeer() == peer.id())
        WriteMessage(line);
    else
        WriteMessage("[#" + std::to_string(peer.id()) + " " +
                     colorNick(peer.nickname()) + "] (new message) " + data.text);
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

/* ---------- contacts, approval, bans and anti-flood ---------- */

namespace
{

std::string banKeyFor(const std::string& destination, const std::string& fingerprint)
{
    if (!destination.empty())
        return "d:" + destination;
    if (!fingerprint.empty())
        return "f:" + fingerprint;
    return {};
}

bool decodeContactSecret(const std::string& secret,
                         std::vector<std::uint8_t>& out)
{
    out.clear();
    if (base64Decode(secret, out) && !out.empty())
        return true;

    /* Also accept a plain hex secret typed by hand. */
    if (secret.size() % 2 != 0 || secret.empty())
        return false;
    out.clear();
    for (std::size_t i = 0; i < secret.size(); i += 2)
    {
        auto hex = [](char c) -> int {
            if (c >= '0' && c <= '9')
                return c - '0';
            if (c >= 'a' && c <= 'f')
                return c - 'a' + 10;
            if (c >= 'A' && c <= 'F')
                return c - 'A' + 10;
            return -1;
        };
        const int hi = hex(secret[i]);
        const int lo = hex(secret[i + 1]);
        if (hi < 0 || lo < 0)
        {
            out.clear();
            return false;
        }
        out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
    }
    return !out.empty();
}

} // namespace

bool Client::FindContactByDest(const std::string& destination, Contact& out)
{
    std::lock_guard<std::mutex> lk(m_contactsMutex);
    for (const auto& c : m_config.contacts)
    {
        if (c.destination == destination)
        {
            out = c;
            return true;
        }
    }
    return false;
}

int Client::FindContactIndex(const std::string& what)
{
    std::lock_guard<std::mutex> lk(m_contactsMutex);
    try
    {
        const int n = std::stoi(what);
        if (n >= 1 && static_cast<std::size_t>(n) <= m_config.contacts.size())
            return n - 1;
    }
    catch (...)
    {
    }

    const std::string needle = lower(what);
    for (std::size_t i = 0; i < m_config.contacts.size(); ++i)
    {
        const Contact& c = m_config.contacts[i];
        if (lower(c.nick) == needle || c.destination == what ||
            lower(fingerprintOf(c.destination)).compare(0, needle.size(), needle) == 0)
            return static_cast<int>(i);
    }
    return -1;
}

std::string Client::MakeContactProof(const Contact& c,
                                     const std::string& transcript) const
{
    std::vector<std::uint8_t> secret;
    if (!decodeContactSecret(c.secret, secret))
        return {};
    const Sha256Digest mac = hmacSha256(secret.data(), secret.size(),
                                        transcript.data(), transcript.size());
    secureZero(secret.data(), secret.size());
    return toHex(mac.data(), mac.size());
}

bool Client::MatchContactProof(const std::string& transcript,
                               const std::string& proof,
                               Contact& matched)
{
    if (proof.empty())
        return false;
    std::lock_guard<std::mutex> lk(m_contactsMutex);
    for (const auto& c : m_config.contacts)
    {
        const std::string expected = MakeContactProof(c, transcript);
        if (!expected.empty() && constantTimeEquals(proof, expected))
        {
            matched = c;
            return true;
        }
    }
    return false;
}

void Client::UpdateContactDestination(const std::string& oldDestination,
                                      const std::string& newDestination)
{
    bool changed = false;
    {
        std::lock_guard<std::mutex> lk(m_contactsMutex);
        for (auto& c : m_config.contacts)
        {
            if (c.destination == oldDestination)
            {
                c.destination = newDestination;
                changed = true;
                break;
            }
        }
    }
    if (changed)
        SaveConfig();
}

void Client::SendContactAdd(const std::shared_ptr<Peer>& peer)
{
    if (!peer || peer->isRelay())
        return;

    const std::string secret = base64Encode(randomBytes(32));
    Contact c;
    c.nick = peer->nickname();
    c.destination = peer->destination();
    c.secret = secret;

    {
        std::lock_guard<std::mutex> lk(m_contactsMutex);
        bool replaced = false;
        for (auto& existing : m_config.contacts)
        {
            if (existing.destination == c.destination)
            {
                existing = c;
                replaced = true;
                break;
            }
        }
        if (!replaced)
            m_config.contacts.push_back(c);
    }
    SaveConfig();

    /* The peer stores the same secret, so future handshakes prove identity. */
    peer->sendEncrypted("CONTACT_ADD", c.nick + "|" + c.secret);
    WriteMessage("[contacts] added " + colorNick(c.nick) +
                 " (#" + std::to_string(peer->id()) + ")");
}

void Client::ForgetFlood(int peerId)
{
    std::lock_guard<std::mutex> lk(m_floodMutex);
    m_flood.erase(peerId);
}

bool Client::CheckFlood(Peer& peer, FloodKind kind, const std::string& text,
                        std::string& reason)
{
    const std::uint64_t now = nowSeconds();
    const unsigned window = std::max(1u, m_config.floodWindowSec);
    const int peerId = peer.id();
    bool warn = false;
    std::vector<int> burstKick;

    reason.clear();
    {
        std::lock_guard<std::mutex> lk(m_floodMutex);
        FloodState& st = m_flood[peerId];
        if (st.windowStart == 0 || now - st.windowStart >= window)
        {
            st = FloodState{};
            st.windowStart = now;
        }

        switch (kind)
        {
        case FloodKind::Message:
            ++st.messages;
            if (!text.empty())
            {
                if (std::find(st.recent.begin(), st.recent.end(), text) !=
                    st.recent.end())
                    ++st.repeats;
                st.recent.push_back(text);
                if (st.recent.size() > 12)
                    st.recent.pop_front();
            }

            if (m_config.floodMessageLimit > 0 &&
                st.messages > m_config.floodMessageLimit)
            {
                reason = "message flood";
                /* Several peers flooding at once: drop all of them that are
                 * already over the limit, not just the current one. */
                for (const auto& it : m_flood)
                {
                    if (it.first != peerId && it.second.windowStart != 0 &&
                        now - it.second.windowStart < window &&
                        m_config.floodMessageLimit > 0 &&
                        it.second.messages > m_config.floodMessageLimit)
                        burstKick.push_back(it.first);
                }
            }
            else if (m_config.floodRepeatLimit > 0 &&
                     st.repeats > m_config.floodRepeatLimit)
            {
                reason = "repeat flood";
            }
            else if (!st.warned && m_config.floodMessageLimit > 0 &&
                     st.messages * 4 >= m_config.floodMessageLimit * 3)
            {
                /* Warn once, at 75% of the limit.  A short burst of normal
                 * messages is nowhere near this, so it never bans. */
                st.warned = true;
                warn = true;
            }
            break;

        case FloodKind::Garbage:
            ++st.garbage;
            if (m_config.floodGarbageLimit > 0 &&
                st.garbage > m_config.floodGarbageLimit)
                reason = "garbage flood";
            break;

        case FloodKind::DhRequest:
            ++st.dh;
            if (m_config.floodDhLimit > 0 &&
                st.dh > m_config.floodDhLimit)
                reason = "DH / rekey flood";
            break;
        }
    }

    if (warn)
    {
        WriteMessage(colorText(
            "warning: #" + std::to_string(peerId) + " " + peer.nickname() +
                " is sending messages very fast (" + std::to_string(window) +
                "s window)",
            "1;33"));
    }

    for (int id : burstKick)
    {
        auto p = FindPeerById(id);
        if (!p)
            continue;
        DropPeer(id, "anti-flood: " + reason);
        BanDestination(p->destination(), p->fingerprint(), reason);
    }

    return !reason.empty();
}

void Client::BanDestination(const std::string& destination,
                            const std::string& fingerprint,
                            const std::string& reason,
                            unsigned seconds)
{
    const std::string key = banKeyFor(destination, fingerprint);
    if (key.empty())
        return;

    const std::uint64_t now = nowSeconds();
    unsigned duration = seconds;
    bool attack = false;

    {
        std::lock_guard<std::mutex> lk(m_banMutex);

        /* Expired entries are useless and would otherwise grow forever. */
        for (auto it = m_bans.begin(); it != m_bans.end();)
        {
            if (it->second.until <= now)
                it = m_bans.erase(it);
            else
                ++it;
        }

        auto usedBytes = [this]() {
            std::size_t total = 0;
            for (const auto& it : m_bans)
                total += it.first.size() + it.second.destination.size() +
                         it.second.fingerprint.size() + it.second.reason.size() + 96;
            return total;
        };
        auto enterAttack = [&]() {
            if (m_attackModeUntil <= now)
            {
                m_attackModeUntil = now + 300;
                attack = true;
            }
        };

        const std::size_t limit =
            static_cast<std::size_t>(m_config.banMemoryLimitMb) * 1024 * 1024;
        const bool manual = reason == "manual ban";

        /*
         * A targeted attack can fill the ban table faster than the bans
         * expire.  Once the configured memory budget is reached, stop adding
         * automatic bans and ignore unknown peers for a few minutes instead.
         * Explicit /ban entries are still honoured.
         */
        if (!manual && limit > 0 && usedBytes() >= limit)
        {
            enterAttack();
        }
        else
        {
            BanEntry& e = m_bans[key];
            if (e.destination.empty())
                e.destination = destination;
            if (e.fingerprint.empty())
                e.fingerprint = fingerprint;
            ++e.stage;

            if (duration == 0)
            {
                duration = std::max(1u, m_config.banInitialSeconds);
                for (unsigned i = 1; i < e.stage; ++i)
                {
                    if (duration >= m_config.banMaxSeconds / 2)
                    {
                        duration = m_config.banMaxSeconds;
                        break;
                    }
                    duration *= 2;
                }
                duration = std::min(duration,
                                   std::max(1u, m_config.banMaxSeconds));
            }
            e.until = now + duration;
            e.reason = reason;

            if (!manual && limit > 0 && usedBytes() > limit)
                enterAttack();
        }
    }

    if (attack)
    {
        WriteMessage(colorText(
            "[!] ban memory limit reached: targeted attack detected. "
            "New unknown peers are ignored for 5 minutes. Consider changing "
            "your Destination (/reidentity).",
            "1;31"));
    }
}

bool Client::IsBanned(const std::string& destination,
                      const std::string& fingerprint,
                      std::string& reason)
{
    const std::uint64_t now = nowSeconds();
    std::lock_guard<std::mutex> lk(m_banMutex);
    for (const auto& it : m_bans)
    {
        const BanEntry& e = it.second;
        if ((!destination.empty() && e.destination == destination) ||
            (!fingerprint.empty() && e.fingerprint == fingerprint))
        {
            if (e.until > now)
            {
                reason = e.reason;
                return true;
            }
        }
    }
    return false;
}

void Client::DropBannedPeers(const std::string& destination,
                             const std::string& fingerprint)
{
    for (const auto& p : SnapshotPeers())
    {
        if ((!destination.empty() && p->destination() == destination) ||
            (!fingerprint.empty() && p->fingerprint() == fingerprint))
            DropPeer(p->id(), "banned");
    }
}

bool Client::BanMemoryExceeded()
{
    std::lock_guard<std::mutex> lk(m_banMutex);
    std::size_t total = 0;
    for (const auto& it : m_bans)
        total += it.first.size() + it.second.destination.size() +
                 it.second.fingerprint.size() + it.second.reason.size() + 96;
    return m_config.banMemoryLimitMb > 0 &&
           total > static_cast<std::size_t>(m_config.banMemoryLimitMb) * 1024 * 1024;
}

void Client::EnterAttackMode()
{
    const std::uint64_t now = nowSeconds();
    bool show = false;
    {
        std::lock_guard<std::mutex> lk(m_banMutex);
        if (m_attackModeUntil <= now)
        {
            m_attackModeUntil = now + 300;
            show = true;
        }
    }
    if (show)
        WriteMessage(colorText("[!] targeted attack detected; ignoring unknown "
                               "peers for 5 minutes",
                               "1;31"));
}

void Client::ExpirePending()
{
    std::vector<int> expired;
    const std::uint64_t now = nowSeconds();
    {
        std::lock_guard<std::mutex> lk(m_pendingMutex);
        for (const auto& it : m_pending)
        {
            if (it.second && it.second->expires <= now)
                expired.push_back(it.first);
        }
    }
    for (int id : expired)
        DenyPending(id);
}

bool Client::AcceptPending(int id)
{
    std::shared_ptr<PendingPeer> pending;
    {
        std::lock_guard<std::mutex> lk(m_pendingMutex);
        auto it = m_pending.find(id);
        if (it == m_pending.end())
            return false;
        pending = it->second;
        m_pending.erase(it);
    }
    if (!pending)
        return false;

    auto peer = RegisterPeer(std::move(pending->sock),
                             pending->remote,
                             pending->groupP,
                             pending->groupG,
                             pending->key,
                             false,
                             kRelayDirect,
                             false,
                             std::move(pending->pendingRx));
    if (!peer)
        return false;

    WriteMessage(colorText("[+] accepted #" + std::to_string(id) + " " +
                               pending->remote.nick,
                           "1;32"));
    if (ActivePeer() < 0)
        SetActivePeer(peer->id());
    return true;
}

bool Client::DenyPending(int id)
{
    std::shared_ptr<PendingPeer> pending;
    {
        std::lock_guard<std::mutex> lk(m_pendingMutex);
        auto it = m_pending.find(id);
        if (it == m_pending.end())
            return false;
        pending = it->second;
        m_pending.erase(it);
    }
    if (pending && pending->sock)
    {
        pending->sock->write("BYE\n");
        pending->sock->close();
    }
    WriteMessage("[deny] incoming request #" + std::to_string(id) +
                 " was not accepted");
    return true;
}

void Client::ResetReidentity(const std::string& reason)
{
    std::string wiped;
    {
        std::lock_guard<std::mutex> lk(m_reidentMutex);
        m_reidentActive = false;
        wiped.swap(m_reidentNewPriv);
        m_reidentNewPub.clear();
        m_reidentSigType.clear();
        m_reidentWaiting.clear();
        m_reidentDeadline = 0;
    }
    secureWipe(wiped);
    if (!reason.empty())
        WriteMessage(colorText("[reidentity] " + reason, "1;33"));
}

void Client::FinishReidentity()
{
    std::string newPriv;
    std::string newPub;
    std::string newSig;
    {
        std::lock_guard<std::mutex> lk(m_reidentMutex);
        if (!m_reidentActive)
            return;
        newPriv = m_reidentNewPriv;
        newPub = m_reidentNewPub;
        newSig = m_reidentSigType;
        secureWipe(m_reidentNewPriv);
        m_reidentNewPriv.clear();
        m_reidentNewPub.clear();
        m_reidentSigType.clear();
        m_reidentWaiting.clear();
        m_reidentActive = false;
        m_reidentDeadline = 0;
    }

    secureWipe(m_config.privateKey);
    m_config.privateKey = newPriv;
    if (!newSig.empty())
        m_config.samSignatureType = newSig;
    m_config.samSession = "TriMessage-" + Nick() + "-" + randomHex(2);
    secureWipe(newPriv);

    if (!SaveConfig())
    {
        WriteMessage("[!] could not save the new identity; keeping the old one");
        return;
    }

    WriteMessage(colorText("[reidentity] all contacts confirmed the new "
                           "destination. Restarting with the new identity.",
                           "1;32"));
    WriteMessage("new destination: " + newPub);
    WriteMessage("the client will exit now; start it again");
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    ShutdownNow();
}

void Client::OnReidentityRequest(Peer& peer, const std::string& newDestination)
{
    Contact c;
    if (!FindContactByDest(peer.destination(), c))
    {
        WriteMessage(colorText("[!] ignoring /reidentity from a non-contact #" +
                                   std::to_string(peer.id()),
                               "1;31"));
        return;
    }

    const std::string dest = normaliseDestination(newDestination);
    if (dest.empty() || dest == MyPub())
        return;

    peer.sendEncrypted("REIDENTITY_ACK", dest);
    WriteMessage(colorText("[reidentity] contact " + c.nick +
                               " is moving to a new Destination; the contact "
                               "was updated",
                           "1;33"));
    UpdateContactDestination(peer.destination(), dest);
}

void Client::OnReidentityAck(Peer& peer, const std::string& newDestination)
{
    bool done = false;
    {
        std::lock_guard<std::mutex> lk(m_reidentMutex);
        if (!m_reidentActive)
            return;
        if (normaliseDestination(newDestination) != m_reidentNewPub)
            return;
        m_reidentWaiting.erase(peer.destination());
        done = m_reidentWaiting.empty();
    }
    if (done)
        FinishReidentity();
}


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

        if (!isValidNick(cli.nick))
        {
            sendLine("HELLO_REJECT invalid nickname: only ASCII letters, digits, "
                     "'_', '-' and '.' are allowed");
            WriteMessage(colorText("[!] rejected incoming peer with an invalid "
                                   "nickname",
                                   "1;31"));
            return false;
        }

        std::string banReason;
        if (IsBanned(cli.dest, cli.fp, banReason))
        {
            sendLine("HELLO_REJECT banned");
            WriteMessage("[ban] rejected " + shortFp(cli.fp) + " (" +
                         (banReason.empty() ? "banned" : banReason) + ")");
            return false;
        }

        {
            bool attack = false;
            {
                std::lock_guard<std::mutex> lk(m_banMutex);
                attack = m_attackModeUntil > nowSeconds();
            }
            Contact known;
            if (attack && !FindContactByDest(cli.dest, known))
                return false;
        }

        /* Count HELLO/DH attempts per destination; a burst is an attack. */
        bool tooManyDh = false;
        {
            const std::uint64_t now = nowSeconds();
            const unsigned window = std::max(1u, m_config.floodWindowSec);
            std::lock_guard<std::mutex> lk(m_floodMutex);
            auto& attempts = m_dhAttempts[cli.dest];
            while (!attempts.empty() && now - attempts.front() >= window)
                attempts.pop_front();
            attempts.push_back(now);
            if (m_config.floodDhLimit > 0 &&
                attempts.size() > m_config.floodDhLimit)
                tooManyDh = true;
        }
        if (tooManyDh)
        {
            BanDestination(cli.dest, cli.fp, "DH handshake flood");
            sendLine("HELLO_REJECT too many DH requests");
            WriteMessage(colorText("[ban] " + shortFp(cli.fp) +
                                       " is sending too many DH requests",
                                   "1;31"));
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
        const auto authTokens = splitChar(payload2, ' ');
        const std::string dhProof = authTokens.empty() ? std::string() : authTokens[0];
        const std::string contactProof = authTokens.size() >= 2 ? authTokens[1] : std::string();
        if (!constantTimeEquals(dhProof, expected))
        {
            sendLine("AUTH_FAIL");
            WriteMessage("[!] incoming HELLO failed authentication");
            return false;
        }

        Contact matchedContact;
        bool isContact = false;
        Contact exactContact;
        if (FindContactByDest(cli.dest, exactContact))
        {
            const std::string want = MakeContactProof(exactContact, transcript);
            if (contactProof.empty() || want.empty() ||
                !constantTimeEquals(contactProof, want))
            {
                sendLine("AUTH_FAIL contact proof is missing or wrong");
                WriteMessage(colorText(
                    "[!] someone is pretending to be contact " + exactContact.nick +
                        " (wrong contact secret); connection refused",
                    "1;31"));
                return false;
            }
            matchedContact = exactContact;
            isContact = true;
        }
        else if (!contactProof.empty() &&
                 MatchContactProof(transcript, contactProof, matchedContact))
        {
            WriteMessage(colorText(
                "[!] contact " + matchedContact.nick +
                    " is knocking from a NEW Destination. The contact was "
                    "updated after a successful proof.",
                "1;33"));
            UpdateContactDestination(matchedContact.destination, cli.dest);
            matchedContact.destination = cli.dest;
            isContact = true;
        }

        std::string serverAuth = "AUTH " + makeProof(key, transcript, "server");
        if (isContact)
            serverAuth += " " + MakeContactProof(matchedContact, transcript);
        if (!sendLine(serverAuth))
            return false;

        if (!reader.readLine(line))
            return false;
        if (line.find("AUTH_OK") != 0)
            return false;

        if (!samDest.empty())
            cli.dest = samDest;

        if (isContact || m_config.autoAccept)
        {
            RegisterPeer(std::move(sock), cli, cli.p, cli.g, key,
                         false, kRelayDirect, false, reader.takeBuffer());
            return true;
        }

        const int pendingId = m_nextPendingId.fetch_add(1);
        auto pending = std::make_shared<PendingPeer>();
        pending->id = pendingId;
        pending->sock = std::move(sock);
        pending->remote = cli;
        pending->groupP = cli.p;
        pending->groupG = cli.g;
        pending->key = key;
        pending->pendingRx = reader.takeBuffer();
        pending->expires = nowSeconds() + std::max(5u, m_config.waitAcceptTimeSec);
        pending->contact = false;

        /*
         * Keep the approval queue bounded.  A peer that opens many parallel
         * connections must not be able to exhaust memory with pending DH
         * state, even before /accept is used.
         */
        std::vector<std::shared_ptr<PendingPeer>> droppedPending;
        {
            std::lock_guard<std::mutex> lk(m_pendingMutex);
            m_pending[pendingId] = pending;
            while (m_pending.size() > 32)
            {
                auto oldest = m_pending.begin();
                droppedPending.push_back(oldest->second);
                m_pending.erase(oldest);
            }
        }
        for (const auto& old : droppedPending)
        {
            if (old && old->sock)
            {
                old->sock->write("BYE\n");
                old->sock->close();
            }
        }
        if (!droppedPending.empty())
            WriteMessage("[!] too many pending connection requests; the oldest "
                         "ones were denied");

        WriteMessage(colorText(
            "[?] incoming user " + colorNick(cli.nick) +
                " fp=" + shortFp(cli.fp) + " wants to connect. "
                "Use /accept " + std::to_string(pendingId) + " or /deny " +
                std::to_string(pendingId) + " (auto-deny in " +
                std::to_string(m_config.waitAcceptTimeSec) + "s)",
            "1;33"));
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

    Contact targetContact;
    const bool haveContact = FindContactByDest(target, targetContact);

    std::string bannedReason;
    if (IsBanned(target, fingerprintOf(target), bannedReason))
    {
        WriteMessage("[!] destination is banned: " + bannedReason +
                     " (use /delban to remove the ban)");
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
        if (haveContact && !isRelay)
            auth += " " + MakeContactProof(targetContact, transcript);

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
        if (type2 != "AUTH")
        {
            WriteMessage("[!] server failed authentication");
            return nullptr;
        }
        const auto serverAuth = splitChar(payload2, ' ');
        if (serverAuth.empty() ||
            !constantTimeEquals(serverAuth[0], makeProof(key, transcript, "server")))
        {
            WriteMessage("[!] server failed authentication");
            return nullptr;
        }
        if (haveContact && !isRelay)
        {
            const std::string want = MakeContactProof(targetContact, transcript);
            if (serverAuth.size() < 2 || want.empty() ||
                !constantTimeEquals(serverAuth[1], want))
            {
                WriteMessage(colorText(
                    "[!] server does not know the contact secret for " +
                        targetContact.nick + "; connection refused",
                    "1;31"));
                return nullptr;
            }
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

    if (!isValidNick(remote.nick))
    {
        WriteMessage("[!] refusing to register a peer with an invalid nickname");
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
    ForgetFlood(id);
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

    auto floodKick = [&](FloodKind kind, const std::string& text) {
        std::string reason;
        if (!CheckFlood(peer, kind, text, reason))
            return false;
        BanDestination(peer.destination(), peer.fingerprint(), reason);
        DropPeer(peer.id(), "anti-flood: " + reason);
        return true;
    };

    if (type == "MSG")
    {
        std::string plain;
        if (!peer.decrypt(payload, plain))
        {
            if (!floodKick(FloodKind::Garbage, {}))
                WriteMessage("[!] can't decrypt message from #" +
                             std::to_string(peer.id()));
            return true;
        }

        PlainData data;
        if (!parsePlain(plain, data))
        {
            if (!floodKick(FloodKind::Garbage, {}))
                WriteMessage("[!] malformed message from #" +
                             std::to_string(peer.id()));
            return true;
        }

        if (hasForbiddenControlBytes(data.text) ||
            hasForbiddenControlBytes(data.type) ||
            hasForbiddenControlBytes(data.fromFp) ||
            hasForbiddenControlBytes(data.fromNick))
        {
            DropPeer(peer.id(), "forbidden control bytes in a message");
            return false;
        }

        if (!peer.isRelay() && data.fromFp != peer.fingerprint())
        {
            WriteMessage("[!] message from #" + std::to_string(peer.id()) +
                         " has a wrong sender fingerprint");
            return true;
        }

        const bool knownType =
            data.type == "CHAT" || data.type == "PING" || data.type == "PONG" ||
            data.type == "USERS" || data.type == "SERVER" ||
            data.type == "CONTACT_ADD" || data.type == "CONTACT_ADD_OK" ||
            data.type == "REIDENTITY" || data.type == "REIDENTITY_ACK";
        if (!knownType)
        {
            if (!floodKick(FloodKind::Garbage, {}))
                WriteMessage("[!] unknown message type from #" +
                             std::to_string(peer.id()));
            return true;
        }

        if (data.type == "CHAT")
        {
            if (!floodKick(FloodKind::Message, data.text))
                OnChat(peer, data);
            return true;
        }
        if (data.type == "PING")
        {
            if (!floodKick(FloodKind::Message, data.text))
                peer.sendEncrypted("PONG", data.text);
            return true;
        }
        if (data.type == "CONTACT_ADD")
        {
            if (peer.isRelay())
                return true;
            const auto parts = splitChar(data.text, '|');
            if (parts.size() != 2 || !isValidNick(trimCopy(parts[0])))
                return true;
            std::vector<std::uint8_t> secret;
            if (!decodeContactSecret(trimCopy(parts[1]), secret) ||
                secret.size() < 16)
            {
                DropPeer(peer.id(), "invalid contact secret");
                return false;
            }
            Contact c;
            c.nick = trimCopy(parts[0]);
            c.destination = peer.destination();
            c.secret = trimCopy(parts[1]);
            secureZero(secret.data(), secret.size());
            {
                std::lock_guard<std::mutex> lk(m_contactsMutex);
                bool replaced = false;
                for (auto& existing : m_config.contacts)
                {
                    if (existing.destination == c.destination)
                    {
                        existing = c;
                        replaced = true;
                        break;
                    }
                }
                if (!replaced)
                    m_config.contacts.push_back(c);
            }
            SaveConfig();
            peer.sendEncrypted("CONTACT_ADD_OK", c.nick);
            WriteMessage(colorText("[contacts] " + colorNick(peer.nickname()) +
                                       " added you as a contact",
                                   "1;36"));
            return true;
        }
        if (data.type == "CONTACT_ADD_OK")
        {
            WriteMessage(colorText("[contacts] " + colorNick(peer.nickname()) +
                                       " confirmed the contact secret",
                                   "1;36"));
            return true;
        }
        if (data.type == "REIDENTITY")
        {
            OnReidentityRequest(peer, data.text);
            return true;
        }
        if (data.type == "REIDENTITY_ACK")
        {
            OnReidentityAck(peer, data.text);
            return true;
        }
        if (data.type == "USERS" && peer.isRelay())
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
                         colorNick(peer.nickname()) + ": " +
                         std::to_string(ms) + " ms");
        return true;
    }

    if (type == "NICK")
    {
        std::vector<std::uint8_t> raw;
        if (base64Decode(payload, raw))
        {
            const std::string n(raw.begin(), raw.end());
            if (!isValidNick(n))
            {
                DropPeer(peer.id(), "invalid nickname (non-ASCII or illegal characters)");
                return false;
            }
            peer.setNickname(n);
            WriteMessage("[nick] #" + std::to_string(peer.id()) + " is now " +
                         colorNick(peer.nickname()));
        }
        return true;
    }

    if (type == "REKEY")
    {
        if (floodKick(FloodKind::DhRequest, {}))
            return false;
        if (peer.handleRekey(payload))
            WriteMessage("[rekey] key refresh requested by #" +
                         std::to_string(peer.id()) + " " +
                         colorNick(peer.nickname()));
        return true;
    }

    if (type == "REKEY_ACK")
    {
        if (peer.handleRekeyAck(payload))
            WriteMessage("[rekey] key refreshed with #" + std::to_string(peer.id()) +
                         " " + colorNick(peer.nickname()));
        return true;
    }

    if (type == "REKEY_DONE")
    {
        if (peer.handleRekeyDone(payload))
            WriteMessage("[rekey] key refresh confirmed by #" +
                         std::to_string(peer.id()) + " " +
                         colorNick(peer.nickname()));
        return true;
    }

    if (type == "BYE" || type == "AUTH_FAIL")
        return false;

    if (!floodKick(FloodKind::Garbage, {}))
        WriteMessage("[!] unknown line from #" + std::to_string(peer.id()));
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
        ExpirePending();
        {
            bool expired = false;
            {
                std::lock_guard<std::mutex> lk(m_reidentMutex);
                expired = m_reidentActive && m_reidentDeadline != 0 &&
                          now >= m_reidentDeadline;
            }
            if (expired)
                ResetReidentity("not all contacts confirmed in time; "
                                "identity was not changed");
        }
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
    WriteMessage("/accept <id|all>      - accept an incoming connection request");
    WriteMessage("/deny <id|all>        - reject an incoming connection request");
    WriteMessage("/ban <id|nick|dest> [minutes] - ban a peer (default rising time)");
    WriteMessage("/banlist              - show active bans");
    WriteMessage("/delban <n|dest|fp|all> - remove a ban");
    WriteMessage("/contacts [list]      - contacts and their online state");
    WriteMessage("/contacts add <id|nick> | add <dest> [nick] [secret]");
    WriteMessage("/contacts del <n|nick|dest>");
    WriteMessage("/contacts connect <n|nick|dest> | connectall");
    WriteMessage("/reidentity           - ask contacts to accept a new Destination");
    WriteMessage("/nick <name>          - change my nickname (ASCII only)");
    WriteMessage("/rekey [id|nick]      - force a new DH exchange");
    WriteMessage("/settings [key value] - show or change persistent settings");
    WriteMessage("/decodeconf           - show the decrypted config (secrets hidden)");
    WriteMessage("/p, /panic            - broadcast panic to relays, wipe config and exit");
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
        WriteMessage("  #" + std::to_string(p->id()) + " " + colorNick(p->nickname()) +
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
    if (!isValidNick(params[0]))
    {
        WriteMessage("[!] nickname must contain only ASCII letters, digits, "
                     "'_', '-' and '.' (max 32 chars)");
        return true;
    }
    const std::string n = params[0];
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

bool Client::CmdAccept(const ParamsT& params)
{
    if (params.empty())
    {
        WriteMessage("usage: /accept <id|all>   (see pending requests above)");
        return true;
    }

    if (lower(params[0]) == "all")
    {
        std::vector<int> ids;
        {
            std::lock_guard<std::mutex> lk(m_pendingMutex);
            for (const auto& it : m_pending)
                ids.push_back(it.first);
        }
        if (ids.empty())
        {
            WriteMessage("no pending requests");
            return true;
        }
        for (int id : ids)
            AcceptPending(id);
        return true;
    }

    try
    {
        const int id = std::stoi(params[0]);
        if (!AcceptPending(id))
            WriteMessage("no pending request #" + params[0]);
    }
    catch (...)
    {
        WriteMessage("usage: /accept <id|all>");
    }
    return true;
}

bool Client::CmdDeny(const ParamsT& params)
{
    if (params.empty())
    {
        WriteMessage("usage: /deny <id|all>");
        return true;
    }

    if (lower(params[0]) == "all")
    {
        std::vector<int> ids;
        {
            std::lock_guard<std::mutex> lk(m_pendingMutex);
            for (const auto& it : m_pending)
                ids.push_back(it.first);
        }
        for (int id : ids)
            DenyPending(id);
        return true;
    }

    try
    {
        const int id = std::stoi(params[0]);
        if (!DenyPending(id))
            WriteMessage("no pending request #" + params[0]);
    }
    catch (...)
    {
        WriteMessage("usage: /deny <id|all>");
    }
    return true;
}

bool Client::CmdBan(const ParamsT& params)
{
    if (params.empty())
    {
        WriteMessage("usage: /ban <id|nick|destination|fingerprint> [minutes]");
        return true;
    }

    std::string destination;
    std::string fingerprint;
    std::string nick;
    if (auto peer = FindPeer(params[0]))
    {
        destination = peer->destination();
        fingerprint = peer->fingerprint();
        nick = peer->nickname();
    }
    else
    {
        destination = normaliseDestination(params[0]);
        if (destination.empty())
        {
            const std::string t = lower(params[0]);
            bool hex = !t.empty() && t.size() <= 32;
            for (char c : t)
            {
                if (!std::isxdigit(static_cast<unsigned char>(c)))
                {
                    hex = false;
                    break;
                }
            }
            if (hex)
                fingerprint = t;
            else
            {
                const int idx = FindContactIndex(params[0]);
                if (idx >= 0)
                {
                    std::lock_guard<std::mutex> lk(m_contactsMutex);
                    destination = m_config.contacts[static_cast<std::size_t>(idx)].destination;
                    fingerprint = fingerprintOf(destination);
                    nick = m_config.contacts[static_cast<std::size_t>(idx)].nick;
                }
            }
        }
        else
            fingerprint = fingerprintOf(destination);
    }

    if (destination.empty() && fingerprint.empty())
    {
        WriteMessage("[!] /ban expects a connected user, a destination, or a fingerprint");
        return true;
    }

    unsigned seconds = 0;
    if (params.size() >= 2)
    {
        try
        {
            const unsigned long minutes = std::stoul(params[1]);
            seconds = static_cast<unsigned>(std::min<unsigned long>(minutes, 525600) * 60);
        }
        catch (...)
        {
            WriteMessage("[!] invalid ban time (minutes)");
            return true;
        }
    }

    BanDestination(destination, fingerprint, "manual ban", seconds);
    DropBannedPeers(destination, fingerprint);
    WriteMessage(colorText("[ban] " + (nick.empty() ? shortFp(fingerprint) : nick) +
                               " is banned",
                           "1;31"));
    return true;
}

bool Client::CmdBanList(const ParamsT&)
{
    const std::uint64_t now = nowSeconds();
    std::lock_guard<std::mutex> lk(m_banMutex);
    if (m_bans.empty())
    {
        WriteMessage("ban list is empty");
        return true;
    }

    WriteMessage("ban list (" + std::to_string(m_bans.size()) + "):");
    int n = 0;
    for (const auto& it : m_bans)
    {
        ++n;
        const BanEntry& e = it.second;
        const long long left = static_cast<long long>(e.until) -
                               static_cast<long long>(now);
        std::ostringstream os;
        os << "  " << n << ". fp=" << shortFp(e.fingerprint)
           << " stage=" << e.stage
           << " " << (left > 0 ? "expires in " + std::to_string(left) + "s"
                               : std::string("expired"))
           << " reason=" << e.reason;
        WriteMessage(os.str());
    }
    if (now < m_attackModeUntil)
        WriteMessage(colorText("  ATTACK MODE active for another " +
                                   std::to_string(m_attackModeUntil - now) + "s",
                               "1;31"));
    return true;
}

bool Client::CmdDelBan(const ParamsT& params)
{
    if (params.empty())
    {
        WriteMessage("usage: /delban <number|destination|fingerprint|all>");
        return true;
    }

    if (lower(params[0]) == "all")
    {
        std::lock_guard<std::mutex> lk(m_banMutex);
        m_bans.clear();
        m_attackModeUntil = 0;
        WriteMessage("ban list cleared");
        return true;
    }

    std::string target = normaliseDestination(params[0]);
    if (target.empty())
        target = params[0];

    int index = 0;
    try
    {
        index = std::stoi(params[0]);
    }
    catch (...)
    {
        index = 0;
    }

    std::lock_guard<std::mutex> lk(m_banMutex);
    int n = 0;
    for (auto it = m_bans.begin(); it != m_bans.end(); ++it)
    {
        ++n;
        const BanEntry& e = it->second;
        const bool match = (index > 0 && n == index) ||
                           (!target.empty() && (e.destination == target ||
                                                e.fingerprint == target)) ||
                           (!target.empty() && e.fingerprint.compare(0, target.size(),
                                                                      lower(target)) == 0);
        if (match)
        {
            m_bans.erase(it);
            WriteMessage("ban removed");
            return true;
        }
    }
    WriteMessage("no such ban: " + params[0]);
    return true;
}

bool Client::CmdContacts(const ParamsT& params)
{
    const std::string sub = params.empty() ? "list" : lower(params[0]);

    if (sub == "list")
    {
        std::lock_guard<std::mutex> lk(m_contactsMutex);
        if (m_config.contacts.empty())
        {
            WriteMessage("contact list is empty. Use /contacts add <id|nick> "
                         "or /contacts add <destination> [nick] [secret]");
            return true;
        }
        WriteMessage("contacts (" + std::to_string(m_config.contacts.size()) + "):");
        for (std::size_t i = 0; i < m_config.contacts.size(); ++i)
        {
            const Contact& c = m_config.contacts[i];
            bool online = false;
            for (const auto& p : SnapshotPeers())
            {
                if (p->destination() == c.destination)
                {
                    online = true;
                    break;
                }
            }
            WriteMessage("  " + std::to_string(i + 1) + ". " + colorNick(c.nick) +
                         (online ? colorText(" [online]", "1;32")
                                 : colorText(" [offline]", "2")) +
                         " fp=" + shortFp(fingerprintOf(c.destination)));
        }
        return true;
    }

    if (sub == "add")
    {
        if (params.size() < 2)
        {
            WriteMessage("usage: /contacts add <id|nick> | "
                         "/contacts add <destination> [nick] [secret]");
            return true;
        }

        if (auto peer = FindPeer(params[1]))
        {
            if (peer->isRelay())
            {
                WriteMessage("[!] a relay cannot be a contact");
                return true;
            }
            SendContactAdd(peer);
            return true;
        }

        const std::string dest = normaliseDestination(params[1]);
        if (dest.empty())
        {
            WriteMessage("[!] not a connected user and not a full I2P destination");
            return true;
        }

        Contact c;
        c.destination = dest;
        c.nick = params.size() >= 3 ? params[2]
                                    : "contact" + std::to_string(m_config.contacts.size() + 1);
        if (!isValidNick(c.nick))
        {
            WriteMessage("[!] contact nickname must be ASCII letters, digits, "
                         "'_', '-' or '.'");
            return true;
        }

        bool generated = false;
        if (params.size() >= 4)
        {
            std::vector<std::uint8_t> secret;
            if (!decodeContactSecret(params[3], secret))
            {
                WriteMessage("[!] contact secret must be base64 or hex");
                return true;
            }
            c.secret = params[3];
        }
        else
        {
            c.secret = base64Encode(randomBytes(32));
            generated = true;
        }

        {
            std::lock_guard<std::mutex> lk(m_contactsMutex);
            bool replaced = false;
            for (auto& existing : m_config.contacts)
            {
                if (existing.destination == c.destination)
                {
                    existing = c;
                    replaced = true;
                    break;
                }
            }
            if (!replaced)
                m_config.contacts.push_back(c);
        }
        SaveConfig();
        WriteMessage("contact " + colorNick(c.nick) + " saved (" +
                     shortFp(fingerprintOf(c.destination)) + ")");
        if (generated)
            WriteMessage("shared secret (give it to the contact out of band): " +
                         c.secret);
        return true;
    }

    if (sub == "del" || sub == "remove" || sub == "rm")
    {
        if (params.size() < 2)
        {
            WriteMessage("usage: /contacts del <number|nick|destination>");
            return true;
        }
        const int idx = FindContactIndex(params[1]);
        if (idx < 0)
        {
            WriteMessage("no such contact: " + params[1]);
            return true;
        }
        std::string nick;
        {
            std::lock_guard<std::mutex> lk(m_contactsMutex);
            nick = m_config.contacts[static_cast<std::size_t>(idx)].nick;
            m_config.contacts.erase(m_config.contacts.begin() + idx);
        }
        SaveConfig();
        WriteMessage("contact " + colorNick(nick) + " removed");
        return true;
    }

    if (sub == "connect")
    {
        if (params.size() < 2)
        {
            WriteMessage("usage: /contacts connect <number|nick|destination>");
            return true;
        }
        std::string dest;
        std::string nick;
        if (const int idx = FindContactIndex(params[1]); idx >= 0)
        {
            std::lock_guard<std::mutex> lk(m_contactsMutex);
            dest = m_config.contacts[static_cast<std::size_t>(idx)].destination;
            nick = m_config.contacts[static_cast<std::size_t>(idx)].nick;
        }
        else
            dest = normaliseDestination(params[1]);

        if (dest.empty())
        {
            WriteMessage("no such contact: " + params[1]);
            return true;
        }
        for (const auto& p : SnapshotPeers())
        {
            if (p->destination() == dest)
            {
                SetActivePeer(p->id());
                WriteMessage("chat with #" + std::to_string(p->id()) + " " +
                             colorNick(p->nickname()));
                PrintPeerHistory(p);
                return true;
            }
        }
        WriteMessage("connecting to " + (nick.empty() ? shortFp(fingerprintOf(dest))
                                                      : nick) + "...");
        auto peer = ConnectTo(dest);
        if (peer)
        {
            SetActivePeer(peer->id());
            WriteMessage("active chat is now #" + std::to_string(peer->id()) + " " +
                         colorNick(peer->nickname()));
        }
        return true;
    }

    if (sub == "connectall")
    {
        std::vector<Contact> contacts;
        {
            std::lock_guard<std::mutex> lk(m_contactsMutex);
            contacts = m_config.contacts;
        }
        if (contacts.empty())
        {
            WriteMessage("contact list is empty");
            return true;
        }
        for (const auto& c : contacts)
        {
            bool connected = false;
            for (const auto& p : SnapshotPeers())
            {
                if (p->destination() == c.destination)
                {
                    connected = true;
                    break;
                }
            }
            if (connected)
            {
                WriteMessage("already connected to " + colorNick(c.nick));
                continue;
            }
            WriteMessage("connecting to " + colorNick(c.nick) + "...");
            ConnectTo(c.destination);
        }
        return true;
    }

    WriteMessage("usage: /contacts [list|add|del|connect|connectall] ...");
    return true;
}

bool Client::CmdReidentity(const ParamsT&)
{
    {
        std::lock_guard<std::mutex> lk(m_reidentMutex);
        if (m_reidentActive)
        {
            WriteMessage("reidentity is already in progress");
            return true;
        }
    }
    if (m_config.contacts.empty())
    {
        WriteMessage("[!] you have no contacts; add at least one first");
        return true;
    }

    std::string newPriv;
    std::string newPub;
    std::string newSig;
    try
    {
        SAM::StreamSession tmp("TriReKey-" + randomHex(4),
                               m_config.samHost, m_config.samPort);
        auto generated = tmp.destGenerate();
        if (!generated.isOk || generated.value.pub.empty() ||
            generated.value.priv.empty())
        {
            WriteMessage("[!] SAM could not generate a new destination");
            return true;
        }
        newPriv = generated.value.priv;
        newPub = generated.value.pub;
        newSig = "DSA_SHA1";
    }
    catch (const std::exception& e)
    {
        WriteMessage(std::string("[!] can't generate a new destination: ") + e.what());
        return true;
    }

    std::vector<std::shared_ptr<Peer>> targets;
    {
        std::lock_guard<std::mutex> lk(m_contactsMutex);
        for (const auto& c : m_config.contacts)
        {
            for (const auto& p : SnapshotPeers())
            {
                if (!p->isRelay() && p->destination() == c.destination)
                {
                    targets.push_back(p);
                    break;
                }
            }
        }
    }
    if (targets.empty())
    {
        secureWipe(newPriv);
        WriteMessage("[!] no contacts are online; /reidentity needs every "
                     "contact to confirm the new destination");
        return true;
    }

    {
        std::lock_guard<std::mutex> lk(m_reidentMutex);
        m_reidentActive = true;
        m_reidentNewPriv = newPriv;
        m_reidentNewPub = newPub;
        m_reidentSigType = newSig;
        m_reidentWaiting.clear();
        for (const auto& p : targets)
            m_reidentWaiting.insert(p->destination());
        m_reidentDeadline = nowSeconds() + 60;
    }
    secureWipe(newPriv);

    for (const auto& p : targets)
    {
        if (!p->sendEncrypted("REIDENTITY", newPub))
        {
            std::lock_guard<std::mutex> lk(m_reidentMutex);
            m_reidentWaiting.erase(p->destination());
        }
        else
            WriteMessage("[reidentity] sent the new destination to " +
                         colorNick(p->nickname()));
    }

    bool done = false;
    {
        std::lock_guard<std::mutex> lk(m_reidentMutex);
        done = m_reidentActive && m_reidentWaiting.empty();
    }
    if (done)
        FinishReidentity();
    else
        WriteMessage("[reidentity] waiting up to 60 seconds for all contacts "
                     "to confirm");
    return true;
}

bool Client::CmdSettings(const ParamsT& params)
{
    if (params.empty())
    {
        WriteMessage("settings (" + m_config.path + "):");
        WriteMessage("  config_encrypted = " +
                     std::string(m_config.configEncrypted ? "true" : "false"));
        WriteMessage("  config_password = " +
                     std::string(m_config.configPassword.empty() ? "(not set)" : "(set, hidden)"));
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
        WriteMessage("  sandbox = " + std::string(m_config.sandboxEnabled ? "true" : "false"));
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
        WriteMessage("  auto_accept = " +
                     std::string(m_config.autoAccept ? "true" : "false"));
        WriteMessage("  wait_accept_time_sec = " +
                     std::to_string(m_config.waitAcceptTimeSec));
        WriteMessage("  flood_window_sec = " + std::to_string(m_config.floodWindowSec));
        WriteMessage("  flood_repeat_limit = " +
                     std::to_string(m_config.floodRepeatLimit));
        WriteMessage("  flood_garbage_limit = " +
                     std::to_string(m_config.floodGarbageLimit));
        WriteMessage("  flood_dh_limit = " + std::to_string(m_config.floodDhLimit));
        WriteMessage("  flood_message_limit = " +
                     std::to_string(m_config.floodMessageLimit));
        WriteMessage("  ban_initial_seconds = " +
                     std::to_string(m_config.banInitialSeconds));
        WriteMessage("  ban_max_seconds = " + std::to_string(m_config.banMaxSeconds));
        WriteMessage("  ban_memory_limit_mb = " +
                     std::to_string(m_config.banMemoryLimitMb));
        WriteMessage("  colors = " + std::string(m_config.colors ? "true" : "false"));
        {
            std::lock_guard<std::mutex> lk(m_contactsMutex);
            WriteMessage("  contacts = " + std::to_string(m_config.contacts.size()));
        }
        WriteMessage("usage: /settings <key> <value>");
        return true;
    }

    if (params.size() < 2)
    {
        const std::string maybeKey = lower(params[0]);
        if (maybeKey != "config_password" && maybeKey != "private_key")
        {
            WriteMessage("usage: /settings <key> <value>");
            return true;
        }
    }

    const std::string key = lower(params[0]);
    const std::string value = params.size() >= 2 ? params[1] : std::string();

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
        std::string newKey = params.size() >= 2 ? joinFrom(params, 1) : std::string();
        if (newKey == "-")
        {
            secureWipe(m_config.privateKey);
            m_config.samSignatureType.clear();
            if (!SaveConfig())
                return true;
            WriteMessage("private_key cleared; a new one is generated on the next start");
            return true;
        }
        if (newKey.empty())
        {
            if (!askPassword("new private_key (hidden, empty cancels): ", newKey))
            {
                WriteMessage("[!] cancelled");
                return true;
            }
        }
        if (newKey.empty())
        {
            WriteMessage("cancelled");
            return true;
        }
        const std::string pub = publicDestinationFromPrivate(newKey);
        if (pub.empty())
        {
            WriteMessage("[!] that is not a valid private I2P destination");
            secureWipe(newKey);
            return true;
        }
        secureWipe(m_config.privateKey);
        m_config.privateKey = newKey;
        const std::string sig = signatureTypeFromPrivate(newKey);
        if (!sig.empty())
            m_config.samSignatureType = sig;
        secureWipe(newKey);
        if (!SaveConfig())
            return true;
        WriteMessage("private_key saved; restart to apply");
        WriteMessage("public destination: " + pub);
        return true;
    }
    if (key == "config_password")
    {
        const std::string oldPassword = m_config.configPassword;
        const bool oldEncrypted = m_config.configEncrypted;

        if (value == "-")
        {
            m_config.configPassword.clear();
            m_config.configEncrypted = false;
            if (!SaveConfig())
            {
                m_config.configPassword = oldPassword;
                m_config.configEncrypted = oldEncrypted;
                return true;
            }
            WriteMessage("config encryption disabled; the file is now plaintext");
            return true;
        }

        std::string first = params.size() >= 2 ? joinFrom(params, 1) : std::string();
        if (first.empty())
        {
            if (!askPassword("new config password: ", first) || first.empty())
            {
                WriteMessage("[!] cancelled");
                return true;
            }
            std::string second;
            if (!askPassword("repeat config password: ", second) || first != second)
            {
                secureWipe(first);
                secureWipe(second);
                WriteMessage("[!] passwords do not match");
                return true;
            }
            secureWipe(second);
        }

        m_config.configPassword = first;
        m_config.configEncrypted = true;
        const bool ok = SaveConfig();
        secureWipe(first);
        if (!ok)
        {
            m_config.configPassword = oldPassword;
            m_config.configEncrypted = oldEncrypted;
            return true;
        }
        WriteMessage("config password changed; the file was re-encrypted");
        return true;
    }
    if (key == "sandbox")
    {
        bool enabled = false;
        if (!parseBoolValue(value, enabled))
            return bad("true/false");
        m_config.sandboxEnabled = enabled;
        SaveConfig();
        WriteMessage("sandbox saved; restart to apply");
        if (!enabled)
            WriteMessage("[!] WARNING: sandbox is disabled");
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
        key == "relay_anonymous" || key == "relay_ask_plain" ||
        key == "auto_accept")
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
        else if (key == "auto_accept")
            m_config.autoAccept = v;
        else
            m_config.relayAskPlain = v;
        SaveConfig();
        if (key == "auto_accept")
            WriteMessage(std::string("auto_accept is now ") +
                         (v ? "on: incoming peers are accepted automatically"
                            : "off: incoming peers need /accept"));
        else if (key != "allow_huge_dh")
            WriteMessage(key + " saved; restart to apply");
        return true;
    }
    if (key == "wait_accept_time_sec")
    {
        unsigned v = 0;
        if (!parseUnsigned(value, v, 5, 3600))
            return bad("5..3600");
        m_config.waitAcceptTimeSec = v;
        SaveConfig();
        return true;
    }
    if (key == "flood_window_sec")
    {
        unsigned v = 0;
        if (!parseUnsigned(value, v, 1, 3600))
            return bad("1..3600");
        m_config.floodWindowSec = v;
        SaveConfig();
        return true;
    }
    if (key == "flood_repeat_limit")
    {
        unsigned v = 0;
        if (!parseUnsigned(value, v, 0, 100000))
            return bad("0..100000");
        m_config.floodRepeatLimit = v;
        SaveConfig();
        return true;
    }
    if (key == "flood_garbage_limit")
    {
        unsigned v = 0;
        if (!parseUnsigned(value, v, 0, 100000))
            return bad("0..100000");
        m_config.floodGarbageLimit = v;
        SaveConfig();
        return true;
    }
    if (key == "flood_dh_limit")
    {
        unsigned v = 0;
        if (!parseUnsigned(value, v, 0, 100000))
            return bad("0..100000");
        m_config.floodDhLimit = v;
        SaveConfig();
        return true;
    }
    if (key == "flood_message_limit")
    {
        unsigned v = 0;
        if (!parseUnsigned(value, v, 0, 100000))
            return bad("0..100000");
        m_config.floodMessageLimit = v;
        SaveConfig();
        return true;
    }
    if (key == "ban_initial_seconds")
    {
        unsigned v = 0;
        if (!parseUnsigned(value, v, 1, 86400 * 30))
            return bad("1..2592000");
        m_config.banInitialSeconds = v;
        SaveConfig();
        return true;
    }
    if (key == "ban_max_seconds")
    {
        unsigned v = 0;
        if (!parseUnsigned(value, v, 1, 86400 * 365))
            return bad("1..31536000");
        m_config.banMaxSeconds = v;
        SaveConfig();
        return true;
    }
    if (key == "ban_memory_limit_mb")
    {
        unsigned v = 0;
        if (!parseUnsigned(value, v, 0, 1024))
            return bad("0..1024");
        m_config.banMemoryLimitMb = v;
        SaveConfig();
        return true;
    }
    if (key == "colors")
    {
        bool v = false;
        if (!parseBoolValue(value, v))
            return bad("true/false");
        m_config.colors = v;
        setColorEnabled(v);
        SaveConfig();
        WriteMessage(std::string("colors ") + (v ? "enabled" : "disabled"));
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
    WriteMessage("known: config_password nick private_key sam_host sam_port "
                 "sam_session sam_signature_type dh_bits group_bits secret_bits "
                 "rekey_secret_bits max_peer_dh_bits allow_huge_dh sandbox "
                 "server_mode daemon_mode relay_version relay_limit "
                 "relay_anonymous relay_ask_plain relay_password auto_accept "
                 "wait_accept_time_sec flood_window_sec flood_repeat_limit "
                 "flood_garbage_limit flood_dh_limit flood_message_limit "
                 "ban_initial_seconds ban_max_seconds ban_memory_limit_mb colors");
    return true;
}

bool Client::CmdDecodeConf(const ParamsT&)
{
    WriteMessage("decrypted config: " + m_config.path + " (" +
                 std::string(m_config.configEncrypted ? "encrypted at rest" : "plaintext") +
                 ")");
    return CmdSettings({});
}

bool Client::CmdPanic(const ParamsT&)
{
    const std::string text = "USER IS PANICKED [BYE...]";
    const auto peers = SnapshotPeers();

    bool sent = false;
    for (const auto& peer : peers)
    {
        if (peer && peer->isRelay() && peer->sendEncrypted("CHAT", text))
            sent = true;
    }
    if (!sent)
        WriteMessage("[panic] no relay connected; nothing to broadcast");

    WriteMessage("[panic] wiping config and secrets, exiting");
    m_running.store(false);

    /* Give the relay a moment to forward CHAT before the socket goes away. */
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    for (const auto& peer : peers)
    {
        peer->sendLine("BYE");
        peer->shutdown();
        peer->wipeSecrets();
    }

    const std::string configPath = m_config.path;
    secureRemoveFile(configPath);
    secureRemoveFile(configPath + ".tmp");
    secureRemoveFile(configPath + ".bak");

    {
        std::lock_guard<std::mutex> lk(m_contactsMutex);
        for (auto& c : m_config.contacts)
        {
            secureWipe(c.nick);
            secureWipe(c.destination);
            secureWipe(c.secret);
        }
        m_config.contacts.clear();
    }
    {
        std::lock_guard<std::mutex> lk(m_banMutex);
        for (auto& it : m_bans)
        {
            secureWipe(it.second.destination);
            secureWipe(it.second.fingerprint);
            secureWipe(it.second.reason);
        }
        m_bans.clear();
    }

    secureWipe(m_config.privateKey);
    secureWipe(m_config.relayPassword);
    secureWipe(m_config.configPassword);
    secureWipe(m_config.nick);
    secureWipe(m_config.samHost);
    secureWipe(m_config.samSession);
    secureWipe(m_config.samSignatureType);
    secureWipe(m_config.path);
    secureWipe(m_nick);
    secureWipe(m_myPub);
    secureWipe(m_myFp);

    std::cout.flush();
    std::_Exit(0);
    return false;
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
             << " " << colorNick(peer->nickname())
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
    {"accept", [](Client& c, ParamsT p) { return c.CmdAccept(p); }},
    {"deny", [](Client& c, ParamsT p) { return c.CmdDeny(p); }},
    {"ban", [](Client& c, ParamsT p) { return c.CmdBan(p); }},
    {"banlist", [](Client& c, ParamsT p) { return c.CmdBanList(p); }},
    {"bans", [](Client& c, ParamsT p) { return c.CmdBanList(p); }},
    {"delban", [](Client& c, ParamsT p) { return c.CmdDelBan(p); }},
    {"unban", [](Client& c, ParamsT p) { return c.CmdDelBan(p); }},
    {"contacts", [](Client& c, ParamsT p) { return c.CmdContacts(p); }},
    {"contact", [](Client& c, ParamsT p) { return c.CmdContacts(p); }},
    {"reidentity", [](Client& c, ParamsT p) { return c.CmdReidentity(p); }},
    {"reid", [](Client& c, ParamsT p) { return c.CmdReidentity(p); }},
    {"nick", [](Client& c, ParamsT p) { return c.CmdNick(p); }},
    {"rekey", [](Client& c, ParamsT p) { return c.CmdRekey(p); }},
    {"settings", [](Client& c, ParamsT p) { return c.CmdSettings(p); }},
    {"set", [](Client& c, ParamsT p) { return c.CmdSettings(p); }},
    {"decodeconf", [](Client& c, ParamsT p) { return c.CmdDecodeConf(p); }},
    {"conf", [](Client& c, ParamsT p) { return c.CmdDecodeConf(p); }},
    {"showconf", [](Client& c, ParamsT p) { return c.CmdDecodeConf(p); }},
    {"panic", [](Client& c, ParamsT p) { return c.CmdPanic(p); }},
    {"p", [](Client& c, ParamsT p) { return c.CmdPanic(p); }},
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
