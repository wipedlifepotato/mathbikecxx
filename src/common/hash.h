/*
 * SHA-256, HMAC-SHA256 and PBKDF2-HMAC-SHA256.
 *
 * They are used only to protect the local config file with a password.  The
 * implementation is deliberately small and dependency-free so that the
 * program keeps building on Linux, the BSDs, macOS and Windows without
 * OpenSSL.
 */
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace TriMessage
{

using Sha256Digest = std::array<std::uint8_t, 32>;

Sha256Digest sha256(const void* data, std::size_t len);
Sha256Digest sha256(const std::string& s);

Sha256Digest hmacSha256(const void* key, std::size_t keyLen,
                        const void* data, std::size_t dataLen);

/* Derives one 32-byte block.  The config code only needs one block. */
Sha256Digest pbkdf2HmacSha256(const std::string& password,
                              const void* salt, std::size_t saltLen,
                              unsigned iterations);

} // namespace TriMessage
