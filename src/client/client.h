#pragma once

#include <atomic>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "i2psam/i2psam.h"

#include "config.h"
#include "common/handshake.h"

#include "client/peer.h"

namespace TriMessage
{

class Client;

using ParamsT = std::vector<std::string>;
using CommandsT = std::map<std::string, std::function<bool(Client&, ParamsT)>>;

class Client final
{
public:
    explicit Client(Config cfg);
    ~Client();

    void Run();
    void ShutdownNow();
    void WriteMessage(const std::string& text);
    bool SaveConfig();

    /* commands */
    bool CmdHelp(const ParamsT& params);
    bool CmdGetMyPubKey(const ParamsT& params);
    bool CmdConnect(const ParamsT& params);
    bool CmdPing(const ParamsT& params);
    bool CmdUsers(const ParamsT& params);
    bool CmdChat(const ParamsT& params);
    bool CmdMsg(const ParamsT& params);
    bool CmdDelUser(const ParamsT& params);
    bool CmdNick(const ParamsT& params);
    bool CmdRekey(const ParamsT& params);
    bool CmdStatus(const ParamsT& params);
    bool CmdSettings(const ParamsT& params);
    bool CmdDecodeConf(const ParamsT& params);
    bool CmdPanic(const ParamsT& params);
    bool CmdQuit(const ParamsT& params);
    bool CmdAccept(const ParamsT& params);
    bool CmdDeny(const ParamsT& params);
    bool CmdBan(const ParamsT& params);
    bool CmdBanList(const ParamsT& params);
    bool CmdDelBan(const ParamsT& params);
    bool CmdContacts(const ParamsT& params);
    bool CmdReidentity(const ParamsT& params);

    std::string Nick();
    void SetNick(const std::string& n);
    std::string MyPub();
    std::string MyFp();

private:
    void AcceptLoop();
    bool HandleIncoming(std::unique_ptr<SAM::I2pSocket> sock);
    std::shared_ptr<Peer> ConnectTo(const std::string& destination);
    void PeerLoop(std::shared_ptr<Peer> peer, std::string pendingRx);
    bool HandlePeerLine(Peer& peer, const std::string& line);
    void OnChat(Peer& peer, const struct PlainData& data);
    void RekeyLoop();

    bool CheckPeerDh(const struct HsData& hs, bool interactive, std::string& reason);
    void RegenerateGroup();

    /* --- contacts, approval, bans and anti-flood --- */
    struct FloodState
    {
        std::uint64_t windowStart = 0;
        unsigned messages = 0;
        unsigned repeats = 0;
        unsigned garbage = 0;
        unsigned dh = 0;
        bool warned = false;
        std::deque<std::string> recent;
    };

    struct BanEntry
    {
        std::string destination;
        std::string fingerprint;
        std::string reason;
        std::uint64_t until = 0;
        unsigned stage = 0;
    };

    struct PendingPeer
    {
        int id = 0;
        std::unique_ptr<SAM::I2pSocket> sock;
        HsData remote;
        std::string groupP;
        std::string groupG;
        KeyMaterial key;
        std::string pendingRx;
        std::uint64_t expires = 0;
        bool contact = false;
        std::string contactNick;
    };

    bool CheckFlood(Peer& peer, bool garbage, bool dhRequest,
                    const std::string& text, std::string& why);
    void ForgetFlood(int peerId);
    void BanDestination(const std::string& destination,
                        const std::string& fingerprint,
                        const std::string& reason,
                        unsigned seconds = 0);
    bool IsBanned(const std::string& destination,
                  const std::string& fingerprint,
                  std::string& reason);
    void DropBannedPeers(const std::string& destination,
                         const std::string& fingerprint);
    bool BanMemoryExceeded();
    void EnterAttackMode();

    bool FindContactByDest(const std::string& destination, Contact& out);
    int FindContactIndex(const std::string& what);
    std::string MakeContactProof(const Contact& c,
                                 const std::string& transcript) const;
    bool MatchContactProof(const std::string& transcript,
                           const std::string& proof,
                           Contact& matched);
    void UpdateContactDestination(const std::string& oldDestination,
                                  const std::string& newDestination);
    void SendContactAdd(const std::shared_ptr<Peer>& peer);

    void ExpirePending();
    bool AcceptPending(int id);
    bool DenyPending(int id);

    void OnReidentityRequest(Peer& peer, const std::string& newDestination);
    void OnReidentityAck(Peer& peer, const std::string& newDestination);
    void FinishReidentity();
    void ResetReidentity(const std::string& reason);

    std::shared_ptr<Peer> RegisterPeer(std::unique_ptr<SAM::I2pSocket> sock,
                                       const struct HsData& remote,
                                       const std::string& groupP,
                                       const std::string& groupG,
                                       const KeyMaterial& key,
                                       bool relay,
                                       std::uint8_t relayVersion,
                                       bool plain,
                                       std::string pendingRx);
    bool DropPeer(int id, const std::string& reason);

    std::shared_ptr<Peer> FindPeer(const std::string& what);
    std::shared_ptr<Peer> FindPeerById(int id);
    std::vector<std::shared_ptr<Peer>> SnapshotPeers();

    int ActivePeer();
    void SetActivePeer(int id);

    void SendChatTo(const std::shared_ptr<Peer>& peer, const std::string& text);
    void PrintPeerHistory(const std::shared_ptr<Peer>& peer);

    void SetRelayRoster(const std::vector<std::string>& roster);
    std::vector<std::string> RelayRoster();

    Config m_config;

    std::unique_ptr<SAM::StreamSession> m_session;
    std::string m_sessionName;

    std::mutex m_nickMutex;
    std::string m_nick;

    std::string m_myPub;
    std::string m_myFp;

    mpz_class m_groupP;
    mpz_class m_groupG;

    std::mutex m_outMutex;
    std::mutex m_peersMutex;
    std::map<int, std::shared_ptr<Peer>> m_peers;
    std::atomic<int> m_activePeer{-1};
    std::atomic<int> m_nextPeerId{1};

    std::mutex m_rosterMutex;
    std::vector<std::string> m_relayRoster;

    std::mutex m_floodMutex;
    std::map<int, FloodState> m_flood;
    std::deque<std::uint64_t> m_globalMessageTimes;

    /* Incoming DH/HELLO attempts per destination, for the DH-flood ban. */
    std::map<std::string, std::deque<std::uint64_t>> m_dhAttempts;

    std::mutex m_banMutex;
    std::map<std::string, BanEntry> m_bans;
    std::uint64_t m_attackModeUntil = 0;

    std::mutex m_contactsMutex;

    std::mutex m_pendingMutex;
    std::map<int, std::shared_ptr<PendingPeer>> m_pending;
    std::atomic<int> m_nextPendingId{1};

    std::mutex m_reidentMutex;
    bool m_reidentActive = false;
    std::string m_reidentNewPriv;
    std::string m_reidentNewPub;
    std::string m_reidentSigType;
    std::set<std::string> m_reidentWaiting;
    std::uint64_t m_reidentDeadline = 0;

    std::atomic<bool> m_running{true};
    std::thread m_acceptThread;
    std::thread m_rekeyThread;
};

} // namespace TriMessage
