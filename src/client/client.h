#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "i2psam/i2psam.h"

#include "config.h"

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
    bool CmdQuit(const ParamsT& params);

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

    std::atomic<bool> m_running{true};
    std::thread m_acceptThread;
    std::thread m_rekeyThread;
};

} // namespace TriMessage
