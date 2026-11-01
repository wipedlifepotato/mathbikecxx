#include "crypto.h"

#include "util.h"

#include "ChaCha20.h"

#include <algorithm>

namespace TriMessage
{

namespace
{

/*
 * A tiny four-lane sponge.  It is not a cryptographic standard, but it is
 * built from the same mixing primitives as the rest of the project and it
 * touches every input byte several times with position-dependent shifts.
 */
struct Sponge
{
    std::uint64_t a;
    std::uint64_t b;
    std::uint64_t c;
    std::uint64_t d;

    explicit Sponge(std::uint64_t domain)
        : a(0xcbf29ce484222325ULL ^ (domain * 0x9e3779b97f4a7c15ULL)),
          b(0x84222325cbf29ce4ULL + domain),
          c(0x9e3779b97f4a7c15ULL ^ (domain << 32)),
          d(0x100000001b3ULL + domain)
    {
    }

    void absorb(const std::uint8_t* data, std::size_t len)
    {
        a ^= static_cast<std::uint64_t>(len) * 0x100000001b3ULL;
        b += static_cast<std::uint64_t>(len) << 17;
        c ^= static_cast<std::uint64_t>(len);

        for (std::size_t i = 0; i < len; ++i)
        {
            const std::uint64_t v = data[i];
            const std::uint64_t pos = i + 1;

            a = rotl64(a ^ (v + 0x9e3779b97f4a7c15ULL), static_cast<unsigned>((i % 23) + 1));
            a *= 0x100000001b3ULL;

            b = rotl64(b + (v << ((i % 7) + 1)) + pos, static_cast<unsigned>((i % 19) + 3));
            b ^= a >> 7;
            b = (b ^ (b >> 30)) * 0xbf58476d1ce4e5b9ULL;

            c += v * (0x9e3779b97f4a7c15ULL + i);
            c = rotl64(c, static_cast<unsigned>((i % 13) + 5));

            d ^= (v + pos) * (0x94d049bb133111ebULL - i);
            d = (d ^ (d >> 27)) * 0x94d049bb133111ebULL;
        }
    }

    std::uint64_t next()
    {
        std::uint64_t z = (a += 0x9e3779b97f4a7c15ULL);
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
        z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
        const std::uint64_t r = z ^ (z >> 31);

        b = rotl64(b ^ r, 17) * 0x100000001b3ULL;
        c += b ^ (c >> 13);
        d ^= rotl64(c, 29) + a;

        return r ^ b ^ c ^ d;
    }
};

std::array<std::uint8_t, 48> squeeze(const std::vector<std::uint8_t>& raw,
                                     std::uint64_t domain)
{
    Sponge sponge(domain);
    sponge.absorb(raw.data(), raw.size());

    std::array<std::uint8_t, 48> out{};
    for (std::size_t i = 0; i < out.size(); i += 8)
    {
        const std::uint64_t v = sponge.next();
        for (std::size_t j = 0; j < 8; ++j)
            out[i + j] = static_cast<std::uint8_t>((v >> (j * 8)) & 0xff);
    }
    return out;
}

} // namespace

std::vector<std::uint8_t> mpzToBytes(const mpz_class& z)
{
    if (z == 0)
        return std::vector<std::uint8_t>{0};

    const std::size_t n = (mpz_sizeinbase(z.get_mpz_t(), 2) + 7) / 8;
    std::vector<std::uint8_t> out(n);
    std::size_t count = 0;
    mpz_export(out.data(), &count, 1, 1, 1, 0, z.get_mpz_t());
    out.resize(count);
    return out;
}

KeyMaterial deriveKey(const mpz_class& shared)
{
    const std::vector<std::uint8_t> raw = mpzToBytes(shared);

    /* Different domains and different squeeze patterns for key and IV. */
    const auto keySeed = squeeze(raw, 0x4b45592d3332ULL); /* "KEY-32" */
    const auto ivSeed = squeeze(raw, 0x49562d3136ULL);    /* "IV-16"  */

    std::array<std::uint8_t, 12> nonce{};
    for (std::size_t i = 0; i < nonce.size(); ++i)
    {
        /* Spread bytes from all over the IV seed, not just its prefix. */
        nonce[i] = static_cast<std::uint8_t>(
            ivSeed[(i * 7 + 3) % ivSeed.size()] ^
            ivSeed[(i * 13 + 11) % ivSeed.size()] ^
            static_cast<std::uint8_t>(i * 0x3d));
    }

    std::array<std::uint8_t, 48> out{};
    i2p::crypto::chacha::Chacha20State st;
    i2p::crypto::chacha::Chacha20Init(st, nonce.data(), keySeed.data(), 0);
    i2p::crypto::chacha::Chacha20Encrypt(st, out.data(), out.size());

    KeyMaterial km;
    std::copy_n(out.begin(), km.key.size(), km.key.begin());
    for (std::size_t i = 0; i < km.iv.size(); ++i)
    {
        /* Mix the second half of the stream with the tail of the IV seed. */
        km.iv[i] = static_cast<std::uint8_t>(
            out[km.key.size() + i] ^ ivSeed[ivSeed.size() - km.iv.size() + i]);
    }
    return km;
}

std::array<std::uint8_t, 12> nonceFromString(const std::string& s)
{
    const std::uint64_t a = fnv1a(s);
    const std::uint64_t b = fnv1a(s, 0x9e3779b97f4a7c15ULL);
    std::array<std::uint8_t, 12> n{};
    for (int i = 0; i < 8; ++i)
        n[i] = static_cast<std::uint8_t>((a >> (i * 8)) & 0xff);
    for (int i = 0; i < 4; ++i)
        n[8 + i] = static_cast<std::uint8_t>((b >> (i * 8)) & 0xff);
    return n;
}

KeyMaterial derivePasswordKey(const std::string& password,
                             const std::string& salt)
{
    std::vector<std::uint8_t> base(password.begin(), password.end());
    base.push_back(0x1f);
    base.insert(base.end(), salt.begin(), salt.end());

    const std::vector<std::uint8_t> saltBytes(salt.begin(), salt.end());
    auto h = squeeze(base, 0x50415353ULL); /* "PASS" */

    /*
     * Iterate so that guessing the password is not a single fast hash.  20k
     * rounds of the small sponge still take only milliseconds with the
     * default CLI, but make offline guessing noticeably more expensive.
     */
    for (unsigned i = 0; i < 20000; ++i)
    {
        std::vector<std::uint8_t> round(h.begin(), h.end());
        round.insert(round.end(), saltBytes.begin(), saltBytes.end());
        h = squeeze(round, 0x50415353ULL + i);
    }

    std::array<std::uint8_t, 12> nonce{};
    for (std::size_t i = 0; i < nonce.size(); ++i)
        nonce[i] = h[i];

    std::array<std::uint8_t, 48> out{};
    i2p::crypto::chacha::Chacha20State st;
    i2p::crypto::chacha::Chacha20Init(st, nonce.data(), h.data(), 0);
    i2p::crypto::chacha::Chacha20Encrypt(st, out.data(), out.size());

    KeyMaterial km;
    std::copy_n(out.begin(), km.key.size(), km.key.begin());
    for (std::size_t i = 0; i < km.iv.size(); ++i)
        km.iv[i] = static_cast<std::uint8_t>(
            out[km.key.size() + i] ^ h[(i * 3 + 7) % h.size()]);
    return km;
}

std::string makePasswordProof(const std::string& password,
                              const std::string& transcript)
{
    const std::uint64_t a = fnv1a(transcript);
    const std::uint64_t b = fnv1a(transcript, 0x9e3779b97f4a7c15ULL);
    std::string salt;
    salt.reserve(16);
    for (int i = 0; i < 8; ++i)
        salt.push_back(static_cast<char>((a >> (i * 8)) & 0xff));
    for (int i = 0; i < 8; ++i)
        salt.push_back(static_cast<char>((b >> (i * 8)) & 0xff));

    const KeyMaterial km = derivePasswordKey(password, salt);
    auto nonce = nonceFromString("password|" + transcript);
    for (std::size_t i = 0; i < nonce.size(); ++i)
        nonce[i] ^= km.iv[i % km.iv.size()];

    std::array<std::uint8_t, 32> mac{};
    i2p::crypto::chacha::Chacha20State st;
    i2p::crypto::chacha::Chacha20Init(st, nonce.data(), km.key.data(), 0);
    i2p::crypto::chacha::Chacha20Encrypt(st, mac.data(), mac.size());
    return base64Encode(mac.data(), mac.size());
}

std::string makeProof(const KeyMaterial& km,
                      const std::string& transcript,
                      const std::string& role)
{
    std::string data = transcript;
    auto nonce = nonceFromString(role + "|" + transcript);
    for (std::size_t i = 0; i < nonce.size(); ++i)
        nonce[i] ^= km.iv[i % km.iv.size()];

    i2p::crypto::chacha::Chacha20State st;
    i2p::crypto::chacha::Chacha20Init(st, nonce.data(), km.key.data(), 0);
    i2p::crypto::chacha::Chacha20Encrypt(
        st, reinterpret_cast<std::uint8_t*>(&data[0]), data.size());
    return base64Encode(data);
}

} // namespace TriMessage
