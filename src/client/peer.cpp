#include "peer.h"

#include "common/frame.h"
#include "common/util.h"

#include "alberthofman.h"

namespace TriMessage
{

Peer::Peer(int id,
           std::unique_ptr<SAM::I2pSocket> sock,
           std::string nickname,
           std::string destination,
           std::string fingerprint,
           std::string groupP,
           std::string groupG,
           const KeyMaterial& key,
           std::string myNick,
           std::string myFp,
           bool relay,
           std::uint8_t relayVersion,
           bool plain,
           unsigned rekeySecretBits)
    : m_id(id),
      m_sock(std::move(sock)),
      m_nickname(std::move(nickname)),
      m_destination(std::move(destination)),
      m_fp(std::move(fingerprint)),
      m_myNick(std::move(myNick)),
      m_myFp(std::move(myFp)),
      m_key(key),
      m_hasKey(!plain && !key.empty()),
      m_groupP(std::move(groupP)),
      m_groupG(std::move(groupG)),
      m_rekeySecretBits(rekeySecretBits),
      m_relay(relay),
      m_plain(plain),
      m_relayVersion(relayVersion)
{
    const std::uint64_t now = nowSeconds();
    m_lastRekeySec.store(now);
    m_lastRxSec.store(now);
    m_lastPingSentSec.store(now);
    m_rekeyIntervalSec.store(kRekeyMinSeconds +
                             (rng64()() % (kRekeyMaxSeconds - kRekeyMinSeconds + 1)));
}

Peer::~Peer()
{
    shutdown();
}

std::string Peer::nickname() const
{
    std::lock_guard<std::mutex> lk(m_infoMutex);
    return m_nickname;
}

std::string Peer::myNickname() const
{
    std::lock_guard<std::mutex> lk(m_infoMutex);
    return m_myNick;
}

std::string Peer::destination() const
{
    std::lock_guard<std::mutex> lk(m_infoMutex);
    return m_destination;
}

std::string Peer::fingerprint() const
{
    std::lock_guard<std::mutex> lk(m_infoMutex);
    return m_fp;
}

void Peer::setNickname(const std::string& n)
{
    std::lock_guard<std::mutex> lk(m_infoMutex);
    m_nickname = sanitizeNick(n);
}

void Peer::setMyNickname(const std::string& n)
{
    std::lock_guard<std::mutex> lk(m_infoMutex);
    m_myNick = sanitizeNick(n);
}

void Peer::resetRekeyClock()
{
    m_lastRekeySec.store(nowSeconds());
    m_rekeyIntervalSec.store(kRekeyMinSeconds +
                             (rng64()() % (kRekeyMaxSeconds - kRekeyMinSeconds + 1)));
}

bool Peer::sendLine(const std::string& line)
{
    std::lock_guard<std::mutex> lk(m_writeMutex);
    if (!m_alive.load() || !m_sock)
        return false;
    if (!m_sock->isOk())
    {
        m_alive.store(false);
        return false;
    }
    m_sock->write(line + "\n");
    if (!m_sock->isOk())
    {
        m_alive.store(false);
        return false;
    }
    return true;
}

bool Peer::sendEncrypted(const std::string& type, const std::string& text)
{
    std::string fp;
    std::string nick;
    {
        std::lock_guard<std::mutex> lk(m_infoMutex);
        nick = m_myNick;
        fp = m_myFp;
    }
    return sendEncrypted(type, text, fp, nick);
}

bool Peer::sendEncrypted(const std::string& type,
                         const std::string& text,
                         const std::string& fromFp,
                         const std::string& fromNick)
{
    const std::string plain = makePlain(type, fromFp, fromNick, text);
    if (m_plain)
        return sendLine("MSG " + encodePlain(plain));

    KeyMaterial key;
    {
        std::lock_guard<std::mutex> lk(m_keyMutex);
        if (!m_hasKey)
            return false;
        key = m_key;
    }
    return sendLine("MSG " + makeFrame(key, plain));
}

bool Peer::decrypt(const std::string& b64frame, std::string& plain)
{
    if (m_plain)
        return decodePlain(b64frame, plain);

    KeyMaterial current;
    KeyMaterial pending;
    bool hasCurrent = false;
    bool hasPending = false;
    {
        std::lock_guard<std::mutex> lk(m_keyMutex);
        current = m_key;
        hasCurrent = m_hasKey;
        pending = m_pendingKey;
        hasPending = m_hasPending;
    }
    if (hasCurrent && decryptFrame(b64frame, current, plain))
        return true;
    if (hasPending && decryptFrame(b64frame, pending, plain))
        return true;
    return false;
}

void Peer::shutdown()
{
    m_alive.store(false);
    std::lock_guard<std::mutex> lk(m_writeMutex);
    if (m_sock)
        m_sock->close();
}

bool Peer::sendPing()
{
    const std::string token = randomHex(8);
    {
        std::lock_guard<std::mutex> lk(m_pingMutex);
        m_pendingPings[token] = std::chrono::steady_clock::now();
    }
    return sendLine("PING " + token);
}

long Peer::handlePong(const std::string& token)
{
    std::chrono::steady_clock::time_point sent;
    {
        std::lock_guard<std::mutex> lk(m_pingMutex);
        auto it = m_pendingPings.find(token);
        if (it == m_pendingPings.end())
            return -1;
        sent = it->second;
        m_pendingPings.erase(it);
    }
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - sent)
                        .count();
    m_lastPingMs.store(static_cast<long>(ms));
    return static_cast<long>(ms);
}

void Peer::addHistory(const std::string& line)
{
    std::lock_guard<std::mutex> lk(m_historyMutex);
    m_history.push_back(line);
    if (m_history.size() > kHistoryLimit)
        m_history.pop_front();
}

std::vector<std::string> Peer::history() const
{
    std::lock_guard<std::mutex> lk(m_historyMutex);
    return std::vector<std::string>(m_history.begin(), m_history.end());
}

bool Peer::beginRekey()
{
    if (!m_alive.load() || !canRekey())
        return false;

    std::shared_ptr<DiffiHofman> dh;
    std::uint64_t gen = 0;
    {
        std::lock_guard<std::mutex> lk(m_keyMutex);
        if (m_rekeyInProgress || m_hasPending)
            return false;
        gen = ++m_lastGen;
        dh = std::make_shared<DiffiHofman>(mpz_class(m_groupP), mpz_class(m_groupG));
        m_pendingDh = dh;
        m_pendingGen = gen;
        m_rekeyInProgress = true;
    }
    const mpz_class pub = dh->getPublicKey(m_rekeySecretBits);
    const std::string payload = std::to_string(gen) + "\n" + pub.get_str();
    if (!sendLine("REKEY " + base64Encode(payload)))
    {
        std::lock_guard<std::mutex> lk(m_keyMutex);
        m_pendingDh.reset();
        m_rekeyInProgress = false;
        return false;
    }
    return true;
}

bool Peer::handleRekey(const std::string& payload)
{
    if (m_plain || m_relay)
        return false;

    std::vector<std::uint8_t> raw;
    if (!base64Decode(payload, raw))
        return false;
    const std::string s(raw.begin(), raw.end());
    const auto f = splitChar(s, '\n');
    if (f.size() != 2)
        return false;

    std::uint64_t gen = 0;
    try
    {
        gen = std::stoull(f[0]);
    }
    catch (...)
    {
        return false;
    }

    DiffiHofman dh{mpz_class(m_groupP), mpz_class(m_groupG)};
    const mpz_class pub = dh.getPublicKey(m_rekeySecretBits);
    const KeyMaterial newKey = deriveKey(dh.getSharedKey(mpz_class(f[1])));
    {
        std::lock_guard<std::mutex> lk(m_keyMutex);
        m_pendingKey = newKey;
        m_hasPending = true;
        m_pendingGen = gen;
        if (gen > m_lastGen)
            m_lastGen = gen;
    }
    const std::string ack = std::to_string(gen) + "\n" + pub.get_str();
    return sendLine("REKEY_ACK " + base64Encode(ack));
}

bool Peer::handleRekeyAck(const std::string& payload)
{
    std::vector<std::uint8_t> raw;
    if (!base64Decode(payload, raw))
        return false;
    const std::string s(raw.begin(), raw.end());
    const auto f = splitChar(s, '\n');
    if (f.size() != 2)
        return false;

    std::uint64_t gen = 0;
    try
    {
        gen = std::stoull(f[0]);
    }
    catch (...)
    {
        return false;
    }

    std::shared_ptr<DiffiHofman> dh;
    {
        std::lock_guard<std::mutex> lk(m_keyMutex);
        if (!m_pendingDh || m_pendingGen != gen)
            return false;
        dh = m_pendingDh;
    }

    const KeyMaterial newKey = deriveKey(dh->getSharedKey(mpz_class(f[1])));
    if (!sendLine("REKEY_DONE " + base64Encode(std::to_string(gen))))
        return false;

    {
        std::lock_guard<std::mutex> lk(m_keyMutex);
        if (m_pendingGen == gen)
        {
            m_key = newKey;
            m_hasKey = true;
            m_hasPending = false;
            m_pendingDh.reset();
            m_rekeyInProgress = false;
        }
    }
    resetRekeyClock();
    return true;
}

bool Peer::handleRekeyDone(const std::string& payload)
{
    std::vector<std::uint8_t> raw;
    if (!base64Decode(payload, raw))
        return false;
    const std::string s(raw.begin(), raw.end());
    std::uint64_t gen = 0;
    try
    {
        gen = std::stoull(s);
    }
    catch (...)
    {
        return false;
    }

    {
        std::lock_guard<std::mutex> lk(m_keyMutex);
        if (m_hasPending && m_pendingGen == gen)
        {
            m_key = m_pendingKey;
            m_hasKey = true;
            m_hasPending = false;
        }
    }
    resetRekeyClock();
    return true;
}

} // namespace TriMessage
