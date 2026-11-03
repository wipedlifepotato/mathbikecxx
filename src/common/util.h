/*
 * Small helpers used by both the client and the relay server.
 * Nothing here knows about SAM or about the chat protocol.
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <random>
#include <string>
#include <vector>

namespace TriMessage
{

std::mt19937_64& rng64();

std::uint64_t nowSeconds();
std::uint64_t rotl64(std::uint64_t v, unsigned n);

std::uint64_t fnv1a(const void* data, std::size_t len,
                    std::uint64_t seed = 1469598103934665603ULL);
std::uint64_t fnv1a(const std::string& s,
                    std::uint64_t seed = 1469598103934665603ULL);

std::string toHex(const std::uint8_t* data, std::size_t len);
std::string toHex(const std::vector<std::uint8_t>& v);

std::string randomHex(std::size_t bytes);
std::vector<std::uint8_t> randomBytes(std::size_t bytes);

std::string fingerprintOf(const std::string& pub);
std::string shortFp(const std::string& fp);

/*
 * Fake fingerprint for anonymous relay mode: start with 16 zero bytes and
 * add triangular(seq) = 1 + 2 + ... + seq from the last byte, carrying into
 * the previous byte whenever 255 is passed.
 */
std::string anonymousFingerprint(std::uint64_t seq);

std::string lower(std::string s);
std::string trimCopy(const std::string& s);

/*
 * Nicknames are deliberately restricted to ASCII letters, digits, '_', '-'
 * and '.'.  The same check is used at startup, on /nick and for every remote
 * nickname, so a Unicode spoof such as "usеr" can never be displayed as
 * "user".
 */
bool isValidNick(const std::string& in);
std::string sanitizeNick(const std::string& in);
std::string sanitizeText(const std::string& in);

/* True when a decrypted chat payload contains C0/C1 control bytes. */
bool hasForbiddenControlBytes(const std::string& in);

/* ANSI colours, controlled by the `colors` config option. */
void setColorEnabled(bool enabled);
bool colorEnabled();
std::string ansiColor(const char* code);
std::string colorText(const std::string& text, const char* code);
std::string colorNick(const std::string& nick);

std::vector<std::string> splitChar(const std::string& s, char sep);
std::vector<std::string> splitArgs(const std::string& line);
std::string joinFrom(const std::vector<std::string>& v, std::size_t from,
                     const std::string& sep = " ");

bool constantTimeEquals(const std::string& a, const std::string& b);

std::string base64Encode(const std::uint8_t* data, std::size_t len);
std::string base64Encode(const std::vector<std::uint8_t>& v);
std::string base64Encode(const std::string& s);
bool base64Decode(const std::string& in, std::vector<std::uint8_t>& out);

/* I2P destinations are standard base64 with two characters replaced. */
std::string i2pBase64ToStd(std::string s);
std::string stdBase64ToI2p(std::string s);
bool isDestinationChar(char c);
bool looksLikeI2pDestination(const std::string& s);
std::string publicDestinationFromPrivate(const std::string& privateDest);
std::string signatureTypeFromPrivate(const std::string& privateDest);
std::string normaliseDestination(const std::string& input);

/* Config file lives next to the binary by default. */
std::string executableDir(const char* argv0);
std::string joinPath(const std::string& dir, const std::string& name);

/* Reads one line from stdin; used only from the interactive thread. */
bool askYesNo(const std::string& prompt, bool defaultYes = false);

/* Reads a password without local echo when stdin is a terminal. */
bool askPassword(const std::string& prompt, std::string& out);

} // namespace TriMessage
