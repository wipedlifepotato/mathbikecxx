#include "hash.h"

#include "platform.h"

#include <cstring>
#include <vector>

namespace TriMessage
{

namespace
{

constexpr std::uint32_t kRound[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

inline std::uint32_t rotr(std::uint32_t v, unsigned n)
{
    return (v >> n) | (v << (32 - n));
}

void compress(std::uint32_t state[8], const std::uint8_t block[64])
{
    std::uint32_t w[64];
    for (unsigned i = 0; i < 16; ++i)
    {
        w[i] = (static_cast<std::uint32_t>(block[i * 4]) << 24) |
               (static_cast<std::uint32_t>(block[i * 4 + 1]) << 16) |
               (static_cast<std::uint32_t>(block[i * 4 + 2]) << 8) |
               static_cast<std::uint32_t>(block[i * 4 + 3]);
    }
    for (unsigned i = 16; i < 64; ++i)
    {
        const std::uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^
                                 (w[i - 15] >> 3);
        const std::uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^
                                 (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    std::uint32_t a = state[0];
    std::uint32_t b = state[1];
    std::uint32_t c = state[2];
    std::uint32_t d = state[3];
    std::uint32_t e = state[4];
    std::uint32_t f = state[5];
    std::uint32_t g = state[6];
    std::uint32_t h = state[7];

    for (unsigned i = 0; i < 64; ++i)
    {
        const std::uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const std::uint32_t ch = (e & f) ^ ((~e) & g);
        const std::uint32_t temp1 = h + s1 + ch + kRound[i] + w[i];
        const std::uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        const std::uint32_t temp2 = s0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

Sha256Digest sha256Raw(const std::uint8_t* data, std::size_t len)
{
    std::uint32_t state[8] = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
    };

    std::size_t offset = 0;
    while (offset + 64 <= len)
    {
        compress(state, data + offset);
        offset += 64;
    }

    std::uint8_t tail[128] = {};
    const std::size_t rest = len - offset;
    if (rest)
        std::memcpy(tail, data + offset, rest);
    tail[rest] = 0x80;
    const std::size_t tailLen = (rest < 56) ? 64 : 128;
    const std::uint64_t bitLen = static_cast<std::uint64_t>(len) * 8;
    for (unsigned i = 0; i < 8; ++i)
        tail[tailLen - 1 - i] = static_cast<std::uint8_t>((bitLen >> (i * 8)) & 0xff);

    compress(state, tail);
    if (tailLen == 128)
        compress(state, tail + 64);

    Sha256Digest out{};
    for (unsigned i = 0; i < 8; ++i)
    {
        out[i * 4] = static_cast<std::uint8_t>((state[i] >> 24) & 0xff);
        out[i * 4 + 1] = static_cast<std::uint8_t>((state[i] >> 16) & 0xff);
        out[i * 4 + 2] = static_cast<std::uint8_t>((state[i] >> 8) & 0xff);
        out[i * 4 + 3] = static_cast<std::uint8_t>(state[i] & 0xff);
    }
    return out;
}

} // namespace

Sha256Digest sha256(const void* data, std::size_t len)
{
    return sha256Raw(static_cast<const std::uint8_t*>(data), len);
}

Sha256Digest sha256(const std::string& s)
{
    return sha256Raw(reinterpret_cast<const std::uint8_t*>(s.data()), s.size());
}

Sha256Digest hmacSha256(const void* key, std::size_t keyLen,
                        const void* data, std::size_t dataLen)
{
    std::uint8_t keyBlock[64] = {};
    if (keyLen > sizeof(keyBlock))
    {
        const Sha256Digest hashed = sha256(key, keyLen);
        std::memcpy(keyBlock, hashed.data(), hashed.size());
    }
    else if (keyLen)
    {
        std::memcpy(keyBlock, key, keyLen);
    }

    std::uint8_t inner[64];
    std::uint8_t outer[64];
    for (std::size_t i = 0; i < sizeof(keyBlock); ++i)
    {
        inner[i] = static_cast<std::uint8_t>(keyBlock[i] ^ 0x36);
        outer[i] = static_cast<std::uint8_t>(keyBlock[i] ^ 0x5c);
    }

    std::vector<std::uint8_t> innerData;
    innerData.reserve(sizeof(inner) + dataLen);
    innerData.insert(innerData.end(), inner, inner + sizeof(inner));
    const auto* p = static_cast<const std::uint8_t*>(data);
    innerData.insert(innerData.end(), p, p + dataLen);
    const Sha256Digest innerHash = sha256(innerData.data(), innerData.size());
    secureWipe(innerData);

    std::vector<std::uint8_t> outerData;
    outerData.reserve(sizeof(outer) + innerHash.size());
    outerData.insert(outerData.end(), outer, outer + sizeof(outer));
    outerData.insert(outerData.end(), innerHash.begin(), innerHash.end());
    const Sha256Digest result = sha256(outerData.data(), outerData.size());
    secureWipe(outerData);

    secureZero(keyBlock, sizeof(keyBlock));
    secureZero(inner, sizeof(inner));
    secureZero(outer, sizeof(outer));
    return result;
}

Sha256Digest pbkdf2HmacSha256(const std::string& password,
                              const void* salt, std::size_t saltLen,
                              unsigned iterations)
{
    std::vector<std::uint8_t> seed(static_cast<const std::uint8_t*>(salt),
                                   static_cast<const std::uint8_t*>(salt) + saltLen);
    seed.push_back(0);
    seed.push_back(0);
    seed.push_back(0);
    seed.push_back(1);

    Sha256Digest u = hmacSha256(password.data(), password.size(),
                                seed.data(), seed.size());
    Sha256Digest result = u;

    for (unsigned i = 1; i < iterations; ++i)
    {
        u = hmacSha256(password.data(), password.size(), u.data(), u.size());
        for (std::size_t j = 0; j < result.size(); ++j)
            result[j] ^= u[j];
    }

    secureWipe(seed);
    secureZero(u.data(), u.size());
    return result;
}

} // namespace TriMessage
