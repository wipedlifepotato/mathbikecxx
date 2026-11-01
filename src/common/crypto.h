/*
 * Key derivation for Diffie-Hellman secrets.
 *
 * The old code only looked at raw[i % raw.size()] for 32 bytes, so for a big
 * DH secret most bytes were ignored and the result was easy to collide.  Here
 * every byte of the shared secret is absorbed by a small sponge, and the key
 * and the IV are squeezed from different domains of that sponge.  The result
 * is then whitened with ChaCha20.
 */
#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include <gmpxx.h>

namespace TriMessage
{

struct KeyMaterial
{
    std::array<std::uint8_t, 32> key{};
    std::array<std::uint8_t, 16> iv{};

    bool empty() const
    {
        for (auto b : key)
            if (b != 0)
                return false;
        for (auto b : iv)
            if (b != 0)
                return false;
        return true;
    }
};

std::vector<std::uint8_t> mpzToBytes(const mpz_class& z);
KeyMaterial deriveKey(const mpz_class& shared);

/* 12-byte ChaCha20 nonce derived from a string (used by AUTH proofs). */
std::array<std::uint8_t, 12> nonceFromString(const std::string& s);

/*
 * AUTH proof: ChaCha20(transcript) keyed with the DH key, with a nonce that
 * depends on the role and the transcript and is mixed with the derived IV.
 */
std::string makeProof(const KeyMaterial& km,
                      const std::string& transcript,
                      const std::string& role);

/* Group password: slow-ish KDF + 32-byte challenge-response proof. */
KeyMaterial derivePasswordKey(const std::string& password,
                             const std::string& salt);
std::string makePasswordProof(const std::string& password,
                              const std::string& transcript);

} // namespace TriMessage
