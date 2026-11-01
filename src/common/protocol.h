#pragma once

#include <cstddef>

namespace TriMessage
{

constexpr unsigned long kRekeyMinSeconds = 300;   /* 5 minutes */
constexpr unsigned long kRekeyMaxSeconds = 900;   /* 15 minutes */
constexpr unsigned long kHeartbeatSeconds = 10;   /* send PING after this much silence */
constexpr unsigned long kPeerTimeoutSeconds = 35; /* drop a peer after this much silence */
constexpr unsigned long kRelayHeartbeatSeconds = 30;
constexpr std::size_t kHistoryLimit = 100;

} // namespace TriMessage
