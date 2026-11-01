#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "i2psam/i2psam.h"

#include "common/crypto.h"
#include "common/protocol.h"
#include "common/util.h"

class DiffiHofman;

namespace TriMessage
{

class Peer
{
public:
    Peer(int id,
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
         unsigned rekeySecretBits);

    ~Peer();

    int id() const { return m_id; }
    bool alive() const { return m_alive.load(); }
    bool isRelay() const { return m_relay; }
    bool isPlain() const { return m_plain; }
    bool canRekey() const { return !m_relay && !m_plain && m_hasKey; }
    std::uint8_t relayVersion() const { return m_relayVersion; }
    SAM::I2pSocket* socket() const { return m_sock.get(); }

    std::string nickname() const;
    std::string myNickname() const;
    std::string destination() const;
    std::string fingerprint() const;

    void setNickname(const std::string& n);
    void setMyNickname(const std::string& n);

    long lastPingMs() const { return m_lastPingMs.load(); }

    void touchRx() { m_lastRxSec.store(nowSeconds()); }
    std::uint64_t lastRxSec() const { return m_lastRxSec.load(); }
    std::uint64_t lastPingSentSec() const { return m_lastPingSentSec.load(); }
    void markPingSent() { m_lastPingSentSec.store(nowSeconds()); }

    std::uint64_t lastRekeySec() const { return m_lastRekeySec.load(); }
    std::uint64_t rekeyIntervalSec() const { return m_rekeyIntervalSec.load(); }
    void resetRekeyClock();

    bool sendLine(const std::string& line);
    bool sendEncrypted(const std::string& type, const std::string& text);
    bool sendEncrypted(const std::string& type,
                       const std::string& text,
                       const std::string& fromFp,
                       const std::string& fromNick);
    bool decrypt(const std::string& b64frame, std::string& plain);

    void shutdown();
    bool sendPing();
    long handlePong(const std::string& token);

    void addHistory(const std::string& line);
    std::vector<std::string> history() const;

    bool beginRekey();
    bool handleRekey(const std::string& payload);
    bool handleRekeyAck(const std::string& payload);
    bool handleRekeyDone(const std::string& payload);

private:
    int m_id;
    std::unique_ptr<SAM::I2pSocket> m_sock;

    mutable std::mutex m_infoMutex;
    std::string m_nickname;
    std::string m_destination;
    std::string m_fp;
    std::string m_myNick;
    std::string m_myFp;

    std::mutex m_writeMutex;
    std::atomic<bool> m_alive{true};
    std::atomic<std::uint64_t> m_lastRxSec{0};
    std::atomic<std::uint64_t> m_lastPingSentSec{0};

    std::mutex m_keyMutex;
    KeyMaterial m_key;
    bool m_hasKey = false;
    KeyMaterial m_pendingKey;
    bool m_hasPending = false;
    std::uint64_t m_pendingGen = 0;
    std::uint64_t m_lastGen = 0;
    bool m_rekeyInProgress = false;
    std::shared_ptr<DiffiHofman> m_pendingDh;

    std::string m_groupP;
    std::string m_groupG;
    unsigned m_rekeySecretBits;

    bool m_relay;
    bool m_plain;
    std::uint8_t m_relayVersion;

    std::mutex m_pingMutex;
    std::map<std::string, std::chrono::steady_clock::time_point> m_pendingPings;
    std::atomic<long> m_lastPingMs{-1};

    std::atomic<std::uint64_t> m_lastRekeySec{0};
    std::atomic<std::uint64_t> m_rekeyIntervalSec{kRekeyMinSeconds};

    mutable std::mutex m_historyMutex;
    std::deque<std::string> m_history;
};

} // namespace TriMessage
