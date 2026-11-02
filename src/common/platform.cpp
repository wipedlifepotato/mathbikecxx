#include "platform.h"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <random>
#include <sys/stat.h>

#if defined(_WIN32)
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#include <windows.h>
#include <bcrypt.h>
#include <conio.h>
#include <direct.h>
#include <io.h>
#if defined(_MSC_VER)
#pragma comment(lib, "bcrypt.lib")
#endif
#else
#include <fcntl.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>
#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__APPLE__)
#include <climits>
#endif
#endif

namespace TriMessage
{

namespace
{

void secureZeroImpl(void* data, std::size_t len)
{
    volatile unsigned char* p = static_cast<volatile unsigned char*>(data);
    while (len-- > 0)
        *p++ = 0;
}

#if defined(_WIN32)
std::string wideToUtf8(const std::wstring& w)
{
    if (w.empty())
        return {};
    const int len = ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(),
                                          static_cast<int>(w.size()), nullptr, 0,
                                          nullptr, nullptr);
    if (len <= 0)
        return {};
    std::string out(static_cast<std::size_t>(len), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()),
                          out.data(), len, nullptr, nullptr);
    return out;
}

std::string argvFallback(const char* argv0)
{
    char buf[MAX_PATH * 4] = {};
    const DWORD n = ::SearchPathA(nullptr, argv0, nullptr,
                                  static_cast<DWORD>(sizeof(buf)), buf, nullptr);
    if (n > 0 && n < sizeof(buf))
        return std::string(buf);
    if (argv0)
    {
        char full[MAX_PATH * 4] = {};
        const DWORD m = ::GetFullPathNameA(argv0, static_cast<DWORD>(sizeof(full)),
                                           full, nullptr);
        if (m > 0 && m < sizeof(full))
            return std::string(full);
    }
    return argv0 ? std::string(argv0) : std::string();
}
#else
std::string realPathOrEmpty(const std::string& path)
{
    char* resolved = ::realpath(path.c_str(), nullptr);
    if (!resolved)
        return {};
    std::string out(resolved);
    std::free(resolved);
    return out;
}

std::string argvFallback(const char* argv0)
{
    if (!argv0 || !*argv0)
        return {};
    const std::string arg = argv0;
    if (arg.find('/') != std::string::npos)
    {
        const std::string resolved = realPathOrEmpty(arg);
        return resolved.empty() ? arg : resolved;
    }

    const char* envPath = std::getenv("PATH");
    if (envPath)
    {
        std::string path = envPath;
        std::size_t start = 0;
        while (start <= path.size())
        {
            const std::size_t end = path.find(':', start);
            const std::string dir = path.substr(start, end == std::string::npos
                                                           ? std::string::npos
                                                           : end - start);
            const std::string candidate =
                (dir.empty() ? std::string(".") : dir) + "/" + arg;
            if (::access(candidate.c_str(), X_OK) == 0)
            {
                const std::string resolved = realPathOrEmpty(candidate);
                return resolved.empty() ? candidate : resolved;
            }
            if (end == std::string::npos)
                break;
            start = end + 1;
        }
    }

    const std::string resolved = realPathOrEmpty(arg);
    return resolved.empty() ? arg : resolved;
}
#endif

} // namespace

std::string executablePath(const char* argv0)
{
#if defined(_WIN32)
    std::wstring buf(32768, L'\0');
    const DWORD n = ::GetModuleFileNameW(nullptr, buf.data(),
                                         static_cast<DWORD>(buf.size()));
    if (n > 0 && n < buf.size())
    {
        buf.resize(n);
        return wideToUtf8(buf);
    }
    return argvFallback(argv0);
#else
#if defined(__linux__)
    char buf[4096] = {};
    const ssize_t n = ::readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n > 0)
    {
        buf[static_cast<std::size_t>(n)] = '\0';
        return std::string(buf);
    }
#elif defined(__FreeBSD__) || defined(__OpenBSD__)
    /* Both systems expose this when procfs is mounted.  Fall back to
     * realpath(argv0) when it is not. */
    char buf[4096] = {};
    const ssize_t n = ::readlink("/proc/curproc/file", buf, sizeof(buf) - 1);
    if (n > 0)
    {
        buf[static_cast<std::size_t>(n)] = '\0';
        return std::string(buf);
    }
#endif
    return argvFallback(argv0);
#endif
}

std::string platformExecutableDir(const char* argv0)
{
    const std::string exe = executablePath(argv0);
    const std::size_t slash = exe.find_last_of("/\\");
    if (slash == std::string::npos)
        return ".";
    if (slash == 0)
        return exe.substr(0, 1);
    return exe.substr(0, slash);
}

bool setWorkingDirectory(const std::string& dir)
{
    if (dir.empty())
        return false;
#if defined(_WIN32)
    return ::_chdir(dir.c_str()) == 0;
#else
    return ::chdir(dir.c_str()) == 0;
#endif
}

bool isInteractiveStdin()
{
#if defined(_WIN32)
    return ::_isatty(::_fileno(stdin)) != 0;
#else
    return ::isatty(STDIN_FILENO) != 0;
#endif
}

bool fileExists(const std::string& path)
{
#if defined(_WIN32)
    const DWORD attrs = ::GetFileAttributesA(path.c_str());
    return attrs != INVALID_FILE_ATTRIBUTES;
#else
    struct stat st{};
    return ::stat(path.c_str(), &st) == 0;
#endif
}

bool secureRandom(void* data, std::size_t len)
{
    if (!data || len == 0)
        return true;

#if defined(_WIN32)
    const NTSTATUS status = ::BCryptGenRandom(
        nullptr, static_cast<PUCHAR>(data), static_cast<ULONG>(len),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status == 0)
        return true;
#else
    const int fd = ::open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd >= 0)
    {
        std::uint8_t* p = static_cast<std::uint8_t*>(data);
        std::size_t left = len;
        bool ok = true;
        while (left > 0)
        {
            const ssize_t n = ::read(fd, p, left);
            if (n <= 0)
            {
                ok = false;
                break;
            }
            p += n;
            left -= static_cast<std::size_t>(n);
        }
        ::close(fd);
        if (ok)
            return true;
    }
#endif

    /* Last resort: the C++ random_device is still better than an all-zero
     * salt/nonce, but a warning is printed by the caller when it matters. */
    std::random_device rd;
    std::uint8_t* p = static_cast<std::uint8_t*>(data);
    for (std::size_t i = 0; i < len; ++i)
        p[i] = static_cast<std::uint8_t>(rd() & 0xff);
    return false;
}

std::vector<std::uint8_t> secureRandomBytes(std::size_t len)
{
    std::vector<std::uint8_t> out(len);
    if (len)
        secureRandom(out.data(), out.size());
    return out;
}

bool readPassword(const std::string& prompt, std::string& out)
{
    out.clear();
    std::cout << prompt << std::flush;

#if defined(_WIN32)
    if (!isInteractiveStdin())
    {
        std::string line;
        if (!std::getline(std::cin, line))
            return false;
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        out = line;
        return true;
    }

    for (;;)
    {
        const int ch = ::_getch();
        if (ch == EOF || ch == 3) /* Ctrl+C */
        {
            std::cout << std::endl;
            return false;
        }
        if (ch == '\r' || ch == '\n')
            break;
        if (ch == '\b' || ch == 127)
        {
            if (!out.empty())
                out.pop_back();
            continue;
        }
        out.push_back(static_cast<char>(ch));
    }
    std::cout << std::endl;
    return true;
#else
    const bool tty = ::isatty(STDIN_FILENO) != 0;
    termios oldState{};
    bool changed = false;
    if (tty && ::tcgetattr(STDIN_FILENO, &oldState) == 0)
    {
        termios newState = oldState;
        newState.c_lflag &= static_cast<tcflag_t>(~ECHO);
        if (::tcsetattr(STDIN_FILENO, TCSAFLUSH, &newState) == 0)
            changed = true;
    }

    std::string line;
    const bool ok = static_cast<bool>(std::getline(std::cin, line));

    if (changed)
    {
        ::tcsetattr(STDIN_FILENO, TCSAFLUSH, &oldState);
        std::cout << std::endl;
    }

    if (!ok)
        return false;
    if (!line.empty() && line.back() == '\r')
        line.pop_back();
    out = line;
    return true;
#endif
}

void secureZero(void* data, std::size_t len)
{
    if (data && len)
        secureZeroImpl(data, len);
}

void secureWipe(std::string& s)
{
    if (!s.empty())
        secureZero(&s[0], s.size());
    s.clear();
}

void secureWipe(std::vector<std::uint8_t>& v)
{
    if (!v.empty())
        secureZero(v.data(), v.size());
    v.clear();
}

bool setFileMode0600(const std::string& path)
{
#if defined(_WIN32)
    return ::_chmod(path.c_str(), _S_IREAD | _S_IWRITE) == 0;
#else
    return ::chmod(path.c_str(), 0600) == 0;
#endif
}

bool replaceFile(const std::string& source, const std::string& destination)
{
#if defined(_WIN32)
    return ::MoveFileExA(source.c_str(), destination.c_str(),
                         MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
#else
    return std::rename(source.c_str(), destination.c_str()) == 0;
#endif
}

bool removeFile(const std::string& path)
{
#if defined(_WIN32)
    if (::DeleteFileA(path.c_str()))
        return true;
    return ::GetLastError() == ERROR_FILE_NOT_FOUND;
#else
    return ::unlink(path.c_str()) == 0 || errno == ENOENT;
#endif
}

bool secureRemoveFile(const std::string& path)
{
    if (!fileExists(path))
        return true;

    std::random_device rd;
    std::uint8_t buf[4096];
    for (std::size_t i = 0; i < sizeof(buf); ++i)
        buf[i] = static_cast<std::uint8_t>(rd() & 0xff);

#if defined(_WIN32)
    ::SetFileAttributesA(path.c_str(), FILE_ATTRIBUTE_NORMAL);
    HANDLE h = ::CreateFileA(path.c_str(), GENERIC_READ | GENERIC_WRITE,
                             FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                             FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE)
    {
        LARGE_INTEGER size{};
        if (::GetFileSizeEx(h, &size) && size.QuadPart > 0)
        {
            LARGE_INTEGER pos{};
            pos.QuadPart = 0;
            ::SetFilePointerEx(h, pos, nullptr, FILE_BEGIN);
            std::uint64_t left = static_cast<std::uint64_t>(size.QuadPart);
            while (left > 0)
            {
                const DWORD chunk = static_cast<DWORD>(
                    std::min<std::uint64_t>(left, sizeof(buf)));
                DWORD written = 0;
                if (!::WriteFile(h, buf, chunk, &written, nullptr) ||
                    written == 0)
                    break;
                left -= written;
            }
            ::FlushFileBuffers(h);
        }
        ::CloseHandle(h);
    }
    return ::DeleteFileA(path.c_str()) != 0 ||
           ::GetLastError() == ERROR_FILE_NOT_FOUND;
#else
    const int fd = ::open(path.c_str(), O_RDWR | O_NOFOLLOW);
    if (fd >= 0)
    {
        struct stat st{};
        if (::fstat(fd, &st) == 0 && st.st_size > 0)
        {
            off_t left = st.st_size;
            while (left > 0)
            {
                const ssize_t chunk = static_cast<ssize_t>(
                    std::min<off_t>(left, static_cast<off_t>(sizeof(buf))));
                const ssize_t written = ::write(fd, buf, static_cast<std::size_t>(chunk));
                if (written <= 0)
                    break;
                left -= written;
            }
            ::fsync(fd);
        }
        ::close(fd);
    }
    return ::unlink(path.c_str()) == 0 || errno == ENOENT;
#endif
}

} // namespace TriMessage
