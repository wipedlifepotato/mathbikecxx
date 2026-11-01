#include "frame.h"

#include "util.h"

#include "trigande.h"
#include "ChaCha20.h"

#include <array>
#include <random>
#include <sstream>

namespace TriMessage
{

namespace
{

void appendU32(std::vector<std::uint8_t>& out, std::uint32_t v)
{
    out.push_back(static_cast<std::uint8_t>((v >> 24) & 0xff));
    out.push_back(static_cast<std::uint8_t>((v >> 16) & 0xff));
    out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xff));
    out.push_back(static_cast<std::uint8_t>(v & 0xff));
}

bool readU32(const std::vector<std::uint8_t>& in, std::size_t& off, std::uint32_t& v)
{
    if (off + 4 > in.size())
        return false;
    v = (static_cast<std::uint32_t>(in[off]) << 24) |
        (static_cast<std::uint32_t>(in[off + 1]) << 16) |
        (static_cast<std::uint32_t>(in[off + 2]) << 8) |
        static_cast<std::uint32_t>(in[off + 3]);
    off += 4;
    return true;
}

std::array<std::uint8_t, 12> frameNonce(const std::vector<std::uint8_t>& salt,
                                        const KeyMaterial& km)
{
    std::array<std::uint8_t, 12> nonce{};
    for (std::size_t i = 0; i < nonce.size(); ++i)
    {
        nonce[i] = static_cast<std::uint8_t>(
            salt[i] ^ km.iv[i] ^ km.iv[12 + (i % 4)]);
    }
    return nonce;
}

} // namespace

std::vector<std::uint8_t> makeTrigPadding(std::size_t len)
{
    std::vector<std::uint8_t> out(len);
    if (len == 0)
        return out;

    std::uniform_real_distribution<double> dist(-100000.0, 100000.0);
    const long acc = 3 + static_cast<long>(rng64()() % 9);
    const mpf_class a = Triangle::sin_deg(dist(rng64()), acc);
    const mpf_class b = Triangle::cos_deg(dist(rng64()), acc);
    const mpf_class c = Triangle::sin_deg(dist(rng64()), acc, true);
    const mpf_class d = Triangle::cos_deg(dist(rng64()), acc, true);

    std::ostringstream os;
    os << a << "|" << b << "|" << c << "|" << d;
    const std::string seed = os.str();

    std::uint64_t state = fnv1a(seed);
    for (std::size_t i = 0; i < len; ++i)
    {
        state += 0x9e3779b97f4a7c15ULL;
        std::uint64_t z = state;
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
        z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
        z ^= z >> 31;
        out[i] = static_cast<std::uint8_t>(z & 0xff);
    }
    return out;
}

std::string makeFrame(const KeyMaterial& km, const std::string& plain)
{
    const std::vector<std::uint8_t> salt = randomBytes(12);
    const std::size_t padLen = static_cast<std::size_t>(rng64()() % (kMaxPadding + 1));
    const std::vector<std::uint8_t> padding = makeTrigPadding(padLen);

    std::vector<std::uint8_t> cipher(plain.begin(), plain.end());
    const auto nonce = frameNonce(salt, km);
    i2p::crypto::chacha::Chacha20State st;
    i2p::crypto::chacha::Chacha20Init(st, nonce.data(), km.key.data(), 0);
    i2p::crypto::chacha::Chacha20Encrypt(st, cipher.data(), cipher.size());

    std::vector<std::uint8_t> frame;
    frame.reserve(1 + 12 + 4 + padLen + 4 + cipher.size());
    frame.push_back(kFrameVersion);
    frame.insert(frame.end(), salt.begin(), salt.end());
    appendU32(frame, static_cast<std::uint32_t>(padLen));
    frame.insert(frame.end(), padding.begin(), padding.end());
    appendU32(frame, static_cast<std::uint32_t>(cipher.size()));
    frame.insert(frame.end(), cipher.begin(), cipher.end());
    return base64Encode(frame);
}

bool parseFrame(const std::vector<std::uint8_t>& frame,
                std::vector<std::uint8_t>& salt,
                std::vector<std::uint8_t>& cipher,
                std::uint8_t& version)
{
    if (frame.size() < 1 + 12 + 4 + 4)
        return false;

    std::size_t off = 0;
    version = frame[off++];
    if (version != kFrameVersion)
        return false;

    salt.assign(frame.begin() + static_cast<std::ptrdiff_t>(off),
                frame.begin() + static_cast<std::ptrdiff_t>(off + 12));
    off += 12;

    std::uint32_t padLen = 0;
    if (!readU32(frame, off, padLen))
        return false;
    if (padLen > kMaxPadding || frame.size() < off + padLen + 4)
        return false;
    off += padLen; /* padding is not used for decryption at all */

    std::uint32_t cipherLen = 0;
    if (!readU32(frame, off, cipherLen))
        return false;
    if (frame.size() != off + cipherLen)
        return false;

    cipher.assign(frame.begin() + static_cast<std::ptrdiff_t>(off), frame.end());
    return true;
}

bool decryptFrame(const std::string& b64frame,
                  const KeyMaterial& km,
                  std::string& plain)
{
    std::vector<std::uint8_t> frame;
    if (!base64Decode(b64frame, frame))
        return false;

    std::vector<std::uint8_t> salt;
    std::vector<std::uint8_t> cipher;
    std::uint8_t version = 0;
    if (!parseFrame(frame, salt, cipher, version))
        return false;

    const auto nonce = frameNonce(salt, km);
    i2p::crypto::chacha::Chacha20State st;
    i2p::crypto::chacha::Chacha20Init(st, nonce.data(), km.key.data(), 0);
    i2p::crypto::chacha::Chacha20Encrypt(st, cipher.data(), cipher.size());

    plain.assign(cipher.begin(), cipher.end());
    return plain.compare(0, std::char_traits<char>::length(kMagic), kMagic) == 0;
}

std::string encodePlain(const std::string& plain)
{
    return base64Encode(plain);
}

bool decodePlain(const std::string& b64, std::string& plain)
{
    std::vector<std::uint8_t> raw;
    if (!base64Decode(b64, raw))
        return false;
    plain.assign(raw.begin(), raw.end());
    return plain.compare(0, std::char_traits<char>::length(kMagic), kMagic) == 0;
}

std::string makePlain(const std::string& type,
                      const std::string& fromFp,
                      const std::string& fromNick,
                      const std::string& text)
{
    return std::string(kMagic) + "\x1f" + sanitizeText(type) + "\x1f" +
           sanitizeText(fromFp) + "\x1f" + sanitizeText(fromNick) + "\x1f" +
           sanitizeText(text);
}

bool parsePlain(const std::string& plain, PlainData& out)
{
    const auto f = splitChar(plain, '\x1f');
    if (f.size() < 5 || f[0] != kMagic)
        return false;
    out.type = f[1];
    out.fromFp = f[2];
    out.fromNick = f[3];
    out.text = joinFrom(f, 4, std::string(1, '\x1f'));
    return true;
}

} // namespace TriMessage
