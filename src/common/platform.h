/*
 * Small platform layer.
 *
 * The chat code itself is portable C++17; everything that differs between
 * Linux, the BSDs, macOS and Windows is collected here.  Keeping it in one
 * place makes the security-sensitive parts (paths, password input, wiping
 * secrets) easy to audit.
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace TriMessage
{

/* Absolute path of the running executable. */
std::string executablePath(const char* argv0);

/* Directory containing the running executable (no trailing slash). */
std::string platformExecutableDir(const char* argv0);

/* Change the process working directory. */
bool setWorkingDirectory(const std::string& dir);

bool isInteractiveStdin();
bool fileExists(const std::string& path);

/* Cryptographically secure random bytes (OS RNG, with a fallback). */
bool secureRandom(void* data, std::size_t len);
std::vector<std::uint8_t> secureRandomBytes(std::size_t len);

/* Reads a password without echo when the terminal supports it. */
bool readPassword(const std::string& prompt, std::string& out);

/* Best-effort secure erase that the optimiser is not allowed to remove. */
void secureZero(void* data, std::size_t len);
void secureWipe(std::string& s);
void secureWipe(std::vector<std::uint8_t>& v);

/* chmod 0600 / equivalent. */
bool setFileMode0600(const std::string& path);

/* Atomically replace destination with source. */
bool replaceFile(const std::string& source, const std::string& destination);

/* Overwrite a file with random bytes, flush it and unlink it. */
bool secureRemoveFile(const std::string& path);

/* Plain remove that also ignores "not found". */
bool removeFile(const std::string& path);

} // namespace TriMessage
