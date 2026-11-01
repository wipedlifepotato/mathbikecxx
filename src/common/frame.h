/*
 * Message framing.
 *
 * Frame (before base64):
 *   version(1) | salt(12) | padLen(4) | padding(padLen) | cipherLen(4) | ciphertext
 *
 * The real ChaCha20 nonce is salt XOR iv, so the IV derived from the DH secret
 * is used on every frame and a fresh random salt is still sent on the wire.
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "crypto.h"

namespace TriMessage
{

constexpr std::size_t kMaxPadding = 768;
constexpr std::size_t kMaxChatBytes = 4000;
constexpr std::uint8_t kFrameVersion = 2;
constexpr const char* kMagic = "TRI2";

std::vector<std::uint8_t> makeTrigPadding(std::size_t len);

std::string makeFrame(const KeyMaterial& km, const std::string& plain);
bool parseFrame(const std::vector<std::uint8_t>& frame,
                std::vector<std::uint8_t>& salt,
                std::vector<std::uint8_t>& cipher,
                std::uint8_t& version);
bool decryptFrame(const std::string& b64frame,
                  const KeyMaterial& km,
                  std::string& plain);

/* Plaintext mode (relay protocol version 3). */
std::string encodePlain(const std::string& plain);
bool decodePlain(const std::string& b64, std::string& plain);

struct PlainData
{
    std::string type;
    std::string fromFp;
    std::string fromNick;
    std::string text;
};

std::string makePlain(const std::string& type,
                      const std::string& fromFp,
                      const std::string& fromNick,
                      const std::string& text);
bool parsePlain(const std::string& plain, PlainData& out);

} // namespace TriMessage
