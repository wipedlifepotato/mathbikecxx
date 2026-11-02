#include "util.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <iostream>
#include <random>
#include <sstream>

#include "platform.h"

namespace TriMessage
{

std::mt19937_64& rng64()
{
    static thread_local std::mt19937_64 gen([]() {
        std::random_device rd;
        return (static_cast<std::uint64_t>(rd()) << 32) | rd();
    }());
    return gen;
}

std::uint64_t nowSeconds()
{
    using namespace std::chrono;
    return static_cast<std::uint64_t>(
        duration_cast<seconds>(steady_clock::now().time_since_epoch()).count());
}

std::uint64_t rotl64(std::uint64_t v, unsigned n)
{
    n &= 63;
    return (v << n) | (v >> ((64 - n) & 63));
}

std::uint64_t fnv1a(const void* data, std::size_t len, std::uint64_t seed)
{
    const auto* p = static_cast<const unsigned char*>(data);
    std::uint64_t h = seed;
    for (std::size_t i = 0; i < len; ++i)
    {
        h ^= p[i];
        h *= 1099511628211ULL;
        h = rotl64(h, 7);
    }
    return h;
}

std::uint64_t fnv1a(const std::string& s, std::uint64_t seed)
{
    return fnv1a(s.data(), s.size(), seed);
}

std::string toHex(const std::uint8_t* data, std::size_t len)
{
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (std::size_t i = 0; i < len; ++i)
    {
        out.push_back(digits[(data[i] >> 4) & 0x0f]);
        out.push_back(digits[data[i] & 0x0f]);
    }
    return out;
}

std::string toHex(const std::vector<std::uint8_t>& v)
{
    return toHex(v.data(), v.size());
}

std::string randomHex(std::size_t bytes)
{
    return toHex(secureRandomBytes(bytes));
}

std::vector<std::uint8_t> randomBytes(std::size_t bytes)
{
    return secureRandomBytes(bytes);
}

std::string fingerprintOf(const std::string& pub)
{
    std::uint64_t a = fnv1a(pub);
    std::uint64_t b = fnv1a(pub, 0x9e3779b97f4a7c15ULL);
    unsigned char folded = 0;
    for (std::size_t i = 0; i < pub.size(); ++i)
    {
        const auto byte = static_cast<unsigned char>(pub[i]);
        folded ^= static_cast<unsigned char>((byte << ((i % 5) + 1)) & 0xff);
        b = rotl64(b ^ (byte + folded), static_cast<unsigned>((i % 11) + 1));
        b *= 0x100000001b3ULL;
    }
    char buf[40];
    std::snprintf(buf, sizeof(buf), "%016llx%016llx",
                  static_cast<unsigned long long>(a),
                  static_cast<unsigned long long>(b));
    return std::string(buf);
}

std::string shortFp(const std::string& fp)
{
    return fp.size() > 12 ? fp.substr(0, 12) : fp;
}

std::string anonymousFingerprint(std::uint64_t seq)
{
    std::array<std::uint8_t, 16> bytes{};
    std::uint64_t value = seq * (seq + 1) / 2; /* 1 + 2 + 3 + ... */

    int pos = static_cast<int>(bytes.size()) - 1;
    while (value > 0 && pos >= 0)
    {
        std::uint64_t carry = value & 0xff;
        value >>= 8;
        int p = pos;
        while (carry > 0 && p >= 0)
        {
            const std::uint64_t sum = static_cast<std::uint64_t>(bytes[p]) + carry;
            bytes[p] = static_cast<std::uint8_t>(sum & 0xff);
            carry = sum >> 8;
            --p;
        }
        --pos;
    }
    return toHex(bytes.data(), bytes.size());
}

std::string lower(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

std::string trimCopy(const std::string& s)
{
    const std::size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos)
        return {};
    const std::size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

std::string sanitizeNick(const std::string& in)
{
    std::string out;
    for (unsigned char c : in)
    {
        if (std::isalnum(c) || c == '_' || c == '-' || c == '.')
            out.push_back(static_cast<char>(c));
        else if (c == ' ')
            out.push_back('_');
        if (out.size() >= 32)
            break;
    }
    if (out.empty())
        out = "user" + randomHex(2);
    return out;
}

std::string sanitizeText(const std::string& in)
{
    std::string out = in;
    for (char& c : out)
    {
        if (c == '\x1f' || c == '\n' || c == '\r' || c == '\0')
            c = ' ';
    }
    return out;
}

std::vector<std::string> splitChar(const std::string& s, char sep)
{
    std::vector<std::string> out;
    std::size_t start = 0;
    while (true)
    {
        const std::size_t pos = s.find(sep, start);
        if (pos == std::string::npos)
        {
            out.push_back(s.substr(start));
            break;
        }
        out.push_back(s.substr(start, pos - start));
        start = pos + 1;
    }
    return out;
}

std::vector<std::string> splitArgs(const std::string& line)
{
    std::istringstream ss(line);
    std::vector<std::string> out;
    std::string item;
    while (ss >> item)
        out.push_back(item);
    return out;
}

std::string joinFrom(const std::vector<std::string>& v, std::size_t from,
                     const std::string& sep)
{
    std::string out;
    for (std::size_t i = from; i < v.size(); ++i)
    {
        if (!out.empty())
            out += sep;
        out += v[i];
    }
    return out;
}

bool constantTimeEquals(const std::string& a, const std::string& b)
{
    if (a.size() != b.size())
        return false;
    unsigned char diff = 0;
    for (std::size_t i = 0; i < a.size(); ++i)
        diff |= static_cast<unsigned char>(a[i] ^ b[i]);
    return diff == 0;
}

/* ---------- base64 ---------- */

namespace
{
const char* kB64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
}

std::string base64Encode(const std::uint8_t* data, std::size_t len)
{
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    for (std::size_t i = 0; i < len; i += 3)
    {
        const std::uint32_t a = data[i];
        const std::uint32_t b = (i + 1 < len) ? data[i + 1] : 0;
        const std::uint32_t c = (i + 2 < len) ? data[i + 2] : 0;
        const std::uint32_t v = (a << 16) | (b << 8) | c;

        out.push_back(kB64[(v >> 18) & 63]);
        out.push_back(kB64[(v >> 12) & 63]);
        out.push_back((i + 1 < len) ? kB64[(v >> 6) & 63] : '=');
        out.push_back((i + 2 < len) ? kB64[v & 63] : '=');
    }
    return out;
}

std::string base64Encode(const std::vector<std::uint8_t>& v)
{
    return base64Encode(v.data(), v.size());
}

std::string base64Encode(const std::string& s)
{
    return base64Encode(reinterpret_cast<const std::uint8_t*>(s.data()), s.size());
}

namespace
{
std::array<int, 256> makeBase64Table()
{
    std::array<int, 256> table{};
    table.fill(-1);
    for (int i = 0; i < 64; ++i)
        table[static_cast<unsigned char>(kB64[i])] = i;
    return table;
}
}

bool base64Decode(const std::string& in, std::vector<std::uint8_t>& out)
{
    static const std::array<int, 256> table = makeBase64Table();

    out.clear();
    int val = 0;
    int bits = -8;
    for (unsigned char c : in)
    {
        if (c == '=' || c == '\n' || c == '\r' || c == ' ' || c == '\t')
            continue;
        const int d = table[c];
        if (d < 0)
            return false;
        val = (val << 6) | d;
        bits += 6;
        if (bits >= 0)
        {
            out.push_back(static_cast<std::uint8_t>((val >> bits) & 0xff));
            bits -= 8;
        }
    }
    return true;
}

/* ---------- I2P destination helpers ---------- */

std::string i2pBase64ToStd(std::string s)
{
    for (char& c : s)
    {
        if (c == '-')
            c = '+';
        else if (c == '~')
            c = '/';
    }
    return s;
}

std::string stdBase64ToI2p(std::string s)
{
    for (char& c : s)
    {
        if (c == '+')
            c = '-';
        else if (c == '/')
            c = '~';
    }
    return s;
}

bool isDestinationChar(char c)
{
    return std::isalnum(static_cast<unsigned char>(c)) ||
           c == '-' || c == '~' || c == '=' || c == '+' || c == '/';
}

bool looksLikeI2pDestination(const std::string& s)
{
    if (s.size() < 300)
        return false;
    for (unsigned char c : s)
        if (!isDestinationChar(static_cast<char>(c)))
            return false;
    return true;
}

/*
 * SESSION STATUS returns Destination || PrivateKey || SigningPrivateKey.
 * STREAM CONNECT expects only the public Destination part, so split it off by
 * parsing the certificate at the end of the Destination.
 */
namespace
{

struct DestinationKeyType
{
    unsigned sigPubLen;
    unsigned sigPrivLen;
    const char* name;
};

const DestinationKeyType kDestinationKeyTypes[] = {
    {128, 20, "DSA_SHA1"},
    {32, 32, "EdDSA_SHA512_Ed25519"},
    {64, 32, "ECDSA_SHA256_P256"},
    {96, 48, "ECDSA_SHA384_P384"},
    {132, 66, "ECDSA_SHA512_P521"},
    {256, 256, "RSA_SHA256_2048"},
    {384, 384, "RSA_SHA384_3072"},
    {512, 512, "RSA_SHA512_4096"}
};

bool splitPrivateDestination(const std::string& privateDest,
                             std::size_t& pubLen,
                             std::string& sigType)
{
    std::vector<std::uint8_t> raw;
    if (!base64Decode(i2pBase64ToStd(privateDest), raw))
        return false;

    for (const auto& t : kDestinationKeyTypes)
    {
        const std::size_t certOff = 256 + t.sigPubLen;
        if (certOff + 3 > raw.size())
            continue;

        const std::size_t certLen =
            (static_cast<std::size_t>(raw[certOff + 1]) << 8) | raw[certOff + 2];
        if (certLen > 1024)
            continue;

        const std::size_t len = certOff + 3 + certLen;
        if (len + 256 + t.sigPrivLen != raw.size())
            continue;

        pubLen = len;
        sigType = t.name;
        return true;
    }
    return false;
}

} // namespace

std::string publicDestinationFromPrivate(const std::string& privateDest)
{
    std::size_t pubLen = 0;
    std::string sigType;
    if (!splitPrivateDestination(privateDest, pubLen, sigType))
        return {};

    std::vector<std::uint8_t> raw;
    if (!base64Decode(i2pBase64ToStd(privateDest), raw))
        return {};

    return stdBase64ToI2p(base64Encode(raw.data(), pubLen));
}

std::string signatureTypeFromPrivate(const std::string& privateDest)
{
    std::size_t pubLen = 0;
    std::string sigType;
    if (!splitPrivateDestination(privateDest, pubLen, sigType))
        return {};
    return sigType;
}

std::string normaliseDestination(const std::string& input)
{
    std::string s = trimCopy(input);
    if (s.empty())
        return {};

    /* Accept the private form printed by /getMyPubKey as well. */
    const std::string pub = publicDestinationFromPrivate(s);
    if (!pub.empty())
        s = pub;

    return looksLikeI2pDestination(s) ? s : std::string();
}

/* ---------- paths / stdin ---------- */

std::string executableDir(const char* argv0)
{
    return platformExecutableDir(argv0);
}

std::string joinPath(const std::string& dir, const std::string& name)
{
    if (dir.empty() || dir == ".")
        return name;
    if (dir.back() == '/')
        return dir + name;
    return dir + "/" + name;
}

bool askYesNo(const std::string& prompt, bool defaultYes)
{
    std::cout << prompt << (defaultYes ? " [Y/n] " : " [y/N] ") << std::flush;
    std::string line;
    if (!std::getline(std::cin, line))
        return false;
    line = lower(trimCopy(line));
    if (line.empty())
        return defaultYes;
    return line == "y" || line == "yes" || line == "д" || line == "да";
}

bool askPassword(const std::string& prompt, std::string& out)
{
    return readPassword(prompt, out);
}

} // namespace TriMessage
