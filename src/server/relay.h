#pragma once

#include <atomic>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "i2psam/i2psam.h"

#include "config.h"
#include "common/crypto.h"

namespace TriMessage
{

/*
 * Relay chat server.
 *
 * Version 2: every participant has its own DH key (a bit smaller than the
 * configured secret size) and the server re-encrypts every chat message for
 * each of them.
 *
 * Version 3: no encryption at all.  Clients are asked for consent before they
 * connect to such a relay.
 */
class RelayServer final
{
public:
    explicit RelayServer(Config cfg);
    ~RelayServer();

    void Run();
    void ShutdownNow();

private:
    struct Participant;

    bool HandleIncoming(std::unique_ptr<SAM::I2pSocket> sock);
    void ReaderLoop(std::shared_ptr<Participant> p);
    bool HandleLine(Participant& p, const std::string& line);
    bool CheckFlood(Participant& p, bool garbage, bool dhRequest,
                    const std::string& text);
    void JanitorLoop();

    bool SendEvent(const std::shared_ptr<Participant>& p,
                   const std::string& type,
                   const std::string& text,
                   const std::string& fromFp,
                   const std::string& fromNick);
    void BroadcastRoster();
    void BroadcastChat(const Participant& from, const std::string& text);
    void Remove(int id, const std::string& reason);

    void Log(const std::string& text);

    Config m_config;
    std::string m_nick;
    std::string m_sessionName;
    std::unique_ptr<SAM::StreamSession> m_session;
    std::string m_myPub;
    std::string m_myFp;

    unsigned m_participantSecretBits = 128;

    std::mutex m_logMutex;
    std::mutex m_partsMutex;
    std::map<int, std::shared_ptr<Participant>> m_parts;
    std::atomic<int> m_nextId{1};

    std::atomic<bool> m_running{true};
    std::thread m_janitorThread;
};

} // namespace TriMessage
