#include "sandbox.h"

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>

#if defined(_WIN32)
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#include <windows.h>
#elif defined(__linux__)
#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#if __has_include(<linux/filter.h>) && __has_include(<linux/seccomp.h>) && \
    __has_include(<linux/audit.h>)
#define TRIGANDE_HAVE_SECCOMP 1
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#endif
#if __has_include(<linux/landlock.h>)
#define TRIGANDE_HAVE_LANDLOCK 1
#include <linux/landlock.h>
#endif
#elif defined(__OpenBSD__)
#include <unistd.h>
#elif defined(__APPLE__)
#include <sandbox.h>
#endif

namespace TriMessage
{

namespace
{

std::string dirName(const std::string& path)
{
    const std::size_t slash = path.find_last_of("/\\");
    if (slash == std::string::npos)
        return ".";
    if (slash == 0)
        return path.substr(0, 1);
    return path.substr(0, slash);
}

#if defined(__linux__) && defined(TRIGANDE_HAVE_LANDLOCK)
long landlockCreateRuleset(const struct landlock_ruleset_attr* attr,
                           std::size_t size, std::uint32_t flags)
{
#ifdef __NR_landlock_create_ruleset
    return ::syscall(__NR_landlock_create_ruleset, attr, size, flags);
#else
    (void)attr;
    (void)size;
    (void)flags;
    errno = ENOSYS;
    return -1;
#endif
}

long landlockAddRule(int rulesetFd, int ruleType, const void* attr,
                     std::uint32_t flags)
{
#ifdef __NR_landlock_add_rule
    return ::syscall(__NR_landlock_add_rule, rulesetFd, ruleType, attr, flags);
#else
    (void)rulesetFd;
    (void)ruleType;
    (void)attr;
    (void)flags;
    errno = ENOSYS;
    return -1;
#endif
}

long landlockRestrictSelf(int rulesetFd, std::uint32_t flags)
{
#ifdef __NR_landlock_restrict_self
    return ::syscall(__NR_landlock_restrict_self, rulesetFd, flags);
#else
    (void)rulesetFd;
    (void)flags;
    errno = ENOSYS;
    return -1;
#endif
}

bool addLandlockPath(int rulesetFd, const std::string& path,
                     std::uint64_t allowed, bool required, std::string& err)
{
    const int fd = ::open(path.c_str(), O_PATH | O_CLOEXEC);
    if (fd < 0)
    {
        if (required)
            err = "can't open " + path + " for Landlock: " + std::strerror(errno);
        return !required;
    }

    struct landlock_path_beneath_attr attr{};
    attr.allowed_access = allowed;
    attr.parent_fd = fd;
    const long rc = landlockAddRule(rulesetFd, LANDLOCK_RULE_PATH_BENEATH,
                                    &attr, 0);
    const int saved = errno;
    ::close(fd);
    if (rc < 0)
    {
        if (required)
            err = "Landlock rule for " + path + " failed: " + std::strerror(saved);
        return !required;
    }
    return true;
}
#endif

#if defined(__linux__) && defined(TRIGANDE_HAVE_SECCOMP)
#if defined(__x86_64__)
constexpr std::uint32_t kSeccompArch = AUDIT_ARCH_X86_64;
#define TRIGANDE_HAVE_SECCOMP_ARCH 1
#elif defined(__aarch64__)
constexpr std::uint32_t kSeccompArch = AUDIT_ARCH_AARCH64;
#define TRIGANDE_HAVE_SECCOMP_ARCH 1
#endif

struct sock_filter loadWord(std::uint32_t offset)
{
    struct sock_filter f{};
    f.code = BPF_LD | BPF_W | BPF_ABS;
    f.k = offset;
    return f;
}

struct sock_filter jumpEqual(std::uint32_t value, std::uint8_t jt,
                             std::uint8_t jf)
{
    struct sock_filter f{};
    f.code = BPF_JMP | BPF_JEQ | BPF_K;
    f.jt = jt;
    f.jf = jf;
    f.k = value;
    return f;
}

struct sock_filter returnValue(std::uint32_t value)
{
    struct sock_filter f{};
    f.code = BPF_RET | BPF_K;
    f.k = value;
    return f;
}

bool applySeccomp(std::string& err)
{
    std::vector<struct sock_filter> filter;
    filter.push_back(loadWord(static_cast<std::uint32_t>(
        offsetof(struct seccomp_data, arch))));
    filter.push_back(jumpEqual(kSeccompArch, 1, 0));
    filter.push_back(returnValue(SECCOMP_RET_KILL_PROCESS));
    filter.push_back(loadWord(static_cast<std::uint32_t>(
        offsetof(struct seccomp_data, nr))));

    const std::uint32_t kill = SECCOMP_RET_KILL_PROCESS;
    auto deny = [&](int nr) {
        filter.push_back(jumpEqual(static_cast<std::uint32_t>(nr), 0, 1));
        filter.push_back(returnValue(kill));
    };

#ifdef __NR_execve
    deny(__NR_execve);
#endif
#ifdef __NR_execveat
    deny(__NR_execveat);
#endif
#ifdef __NR_fork
    deny(__NR_fork);
#endif
#ifdef __NR_vfork
    deny(__NR_vfork);
#endif
#ifdef __NR_ptrace
    deny(__NR_ptrace);
#endif
#ifdef __NR_process_vm_readv
    deny(__NR_process_vm_readv);
#endif
#ifdef __NR_process_vm_writev
    deny(__NR_process_vm_writev);
#endif
#ifdef __NR_mount
    deny(__NR_mount);
#endif
#ifdef __NR_umount2
    deny(__NR_umount2);
#endif
#ifdef __NR_pivot_root
    deny(__NR_pivot_root);
#endif
#ifdef __NR_chroot
    deny(__NR_chroot);
#endif
#ifdef __NR_setns
    deny(__NR_setns);
#endif
#ifdef __NR_unshare
    deny(__NR_unshare);
#endif
#ifdef __NR_bpf
    deny(__NR_bpf);
#endif
#ifdef __NR_keyctl
    deny(__NR_keyctl);
#endif
#ifdef __NR_add_key
    deny(__NR_add_key);
#endif
#ifdef __NR_request_key
    deny(__NR_request_key);
#endif
#ifdef __NR_open_by_handle_at
    deny(__NR_open_by_handle_at);
#endif
#ifdef __NR_name_to_handle_at
    deny(__NR_name_to_handle_at);
#endif
#ifdef __NR_kexec_load
    deny(__NR_kexec_load);
#endif
#ifdef __NR_kexec_file_load
    deny(__NR_kexec_file_load);
#endif
#ifdef __NR_reboot
    deny(__NR_reboot);
#endif
#ifdef __NR_swapon
    deny(__NR_swapon);
#endif
#ifdef __NR_swapoff
    deny(__NR_swapoff);
#endif
#ifdef __NR_init_module
    deny(__NR_init_module);
#endif
#ifdef __NR_finit_module
    deny(__NR_finit_module);
#endif
#ifdef __NR_delete_module
    deny(__NR_delete_module);
#endif
#ifdef __NR_iopl
    deny(__NR_iopl);
#endif
#ifdef __NR_ioperm
    deny(__NR_ioperm);
#endif
#ifdef __NR_personality
    deny(__NR_personality);
#endif
#ifdef __NR_userfaultfd
    deny(__NR_userfaultfd);
#endif
#ifdef __NR_perf_event_open
    deny(__NR_perf_event_open);
#endif
#ifdef __NR_fanotify_init
    deny(__NR_fanotify_init);
#endif
#ifdef __NR_fanotify_mark
    deny(__NR_fanotify_mark);
#endif
#ifdef __NR_io_uring_setup
    deny(__NR_io_uring_setup);
#endif
#ifdef __NR_io_uring_enter
    deny(__NR_io_uring_enter);
#endif
#ifdef __NR_io_uring_register
    deny(__NR_io_uring_register);
#endif

    filter.push_back(returnValue(SECCOMP_RET_ALLOW));

    struct sock_fprog program{};
    program.len = static_cast<unsigned short>(filter.size());
    program.filter = filter.data();

    if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
    {
        err = std::string("PR_SET_NO_NEW_PRIVS failed: ") + std::strerror(errno);
        return false;
    }
    if (::prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program, 0, 0) != 0)
    {
        err = std::string("seccomp filter failed: ") + std::strerror(errno);
        return false;
    }
    return true;
}
#endif

#if defined(__linux__)
bool applyLinux(const SandboxOptions& options, std::string& err)
{
#ifdef TRIGANDE_HAVE_LANDLOCK
    const long abi = landlockCreateRuleset(nullptr, 0,
                                           LANDLOCK_CREATE_RULESET_VERSION);
    if (abi >= 1)
    {
        std::uint64_t access =
            LANDLOCK_ACCESS_FS_EXECUTE |
            LANDLOCK_ACCESS_FS_READ_FILE |
            LANDLOCK_ACCESS_FS_READ_DIR |
            LANDLOCK_ACCESS_FS_WRITE_FILE |
            LANDLOCK_ACCESS_FS_REMOVE_FILE |
            LANDLOCK_ACCESS_FS_REMOVE_DIR |
            LANDLOCK_ACCESS_FS_MAKE_CHAR |
            LANDLOCK_ACCESS_FS_MAKE_DIR |
            LANDLOCK_ACCESS_FS_MAKE_REG |
            LANDLOCK_ACCESS_FS_MAKE_SOCK |
            LANDLOCK_ACCESS_FS_MAKE_FIFO |
            LANDLOCK_ACCESS_FS_MAKE_BLOCK |
            LANDLOCK_ACCESS_FS_MAKE_SYM;
#ifdef LANDLOCK_ACCESS_FS_REFER
        if (abi >= 2)
            access |= LANDLOCK_ACCESS_FS_REFER;
#endif
#ifdef LANDLOCK_ACCESS_FS_TRUNCATE
        if (abi >= 3)
            access |= LANDLOCK_ACCESS_FS_TRUNCATE;
#endif

        struct landlock_ruleset_attr rulesetAttr{};
        rulesetAttr.handled_access_fs = access;
        const int ruleset = static_cast<int>(
            landlockCreateRuleset(&rulesetAttr, sizeof(rulesetAttr), 0));
        if (ruleset < 0)
        {
            err = std::string("landlock_create_ruleset failed: ") +
                  std::strerror(errno);
            return false;
        }

        const std::uint64_t readOnly =
            LANDLOCK_ACCESS_FS_READ_FILE |
            LANDLOCK_ACCESS_FS_READ_DIR |
            LANDLOCK_ACCESS_FS_EXECUTE;
        const std::uint64_t devReadWrite =
            LANDLOCK_ACCESS_FS_READ_FILE |
            LANDLOCK_ACCESS_FS_WRITE_FILE;

        const char* systemPaths[] = {
            "/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc", "/proc/self"
        };
        for (const char* path : systemPaths)
            addLandlockPath(ruleset, path, readOnly, false, err);

        addLandlockPath(ruleset, "/dev/urandom", devReadWrite, false, err);
        addLandlockPath(ruleset, "/dev/null", devReadWrite, false, err);
        addLandlockPath(ruleset, "/dev/tty", devReadWrite, false, err);

        if (!addLandlockPath(ruleset, options.appDir, access, true, err))
        {
            ::close(ruleset);
            return false;
        }
        const std::string configDir = dirName(options.configPath);
        if (configDir != options.appDir)
        {
            if (!addLandlockPath(ruleset, configDir, access, true, err))
            {
                ::close(ruleset);
                return false;
            }
        }

        if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
        {
            err = std::string("PR_SET_NO_NEW_PRIVS failed: ") +
                  std::strerror(errno);
            ::close(ruleset);
            return false;
        }
        if (landlockRestrictSelf(ruleset, 0) < 0)
        {
            err = std::string("landlock_restrict_self failed: ") +
                  std::strerror(errno);
            ::close(ruleset);
            return false;
        }
        ::close(ruleset);
    }
#endif

#ifdef TRIGANDE_HAVE_SECCOMP
#if defined(TRIGANDE_HAVE_SECCOMP_ARCH)
    if (!applySeccomp(err))
        return false;
#else
    err = "seccomp is not implemented for this CPU architecture";
    return false;
#endif
#else
    err = "seccomp headers are not available";
    return false;
#endif

    return true;
}
#endif

#if defined(__OpenBSD__)
bool applyOpenBSD(const SandboxOptions& options, std::string& err)
{
    auto allowRead = [](const char* path) {
        if (path && *path)
            ::unveil(path, "r");
    };

    /*
     * The config file is the only file we need to read and write.  The
     * directory gets "wc" only so the atomic save (tmp + rename) and the
     * optional daemon log can be created; it does not grant read access to
     * other files in it.
     */
    if (::unveil(options.configPath.c_str(), "rwc") < 0)
    {
        err = std::string("unveil(") + options.configPath + ") failed: " +
              std::strerror(errno);
        return false;
    }
    if (::unveil(options.appDir.c_str(), "wc") < 0)
    {
        err = std::string("unveil(") + options.appDir + ") failed: " +
              std::strerror(errno);
        return false;
    }
    const std::string configDir = dirName(options.configPath);
    if (configDir != options.appDir &&
        ::unveil(configDir.c_str(), "wc") < 0)
    {
        err = std::string("unveil(") + configDir + ") failed: " +
              std::strerror(errno);
        return false;
    }

    /*
     * Only runtime data that the already-loaded program may still ask for.
     * Libraries, locales and the executable itself are mapped before the
     * sandbox is installed, so /usr and friends are deliberately not unveiled.
     */
    const char* readPaths[] = {
        "/etc/hosts", "/etc/resolv.conf", "/etc/services",
        "/dev/urandom", "/dev/null", "/dev/tty"
    };
    for (const char* path : readPaths)
        allowRead(path);

    if (::unveil(nullptr, nullptr) < 0)
    {
        err = std::string("unveil lock failed: ") + std::strerror(errno);
        return false;
    }

    if (::pledge("stdio rpath wpath cpath fattr inet unix dns", nullptr) < 0)
    {
        err = std::string("pledge failed: ") + std::strerror(errno);
        return false;
    }
    return true;
}
#endif

#if defined(__APPLE__)
std::string sandboxQuote(const std::string& value)
{
    std::string out;
    out.reserve(value.size() + 8);
    for (char c : value)
    {
        if (c == '\\' || c == '"')
            out.push_back('\\');
        out.push_back(c);
    }
    return out;
}

bool applyMacOS(const SandboxOptions& options, std::string& err)
{
    const std::string app = sandboxQuote(options.appDir);
    const std::string configDir = sandboxQuote(dirName(options.configPath));

    std::ostringstream profile;
    profile
        << "(version 1)\n"
        << "(deny default)\n"
        << "(allow process-fork)\n"
        << "(allow process-info*)\n"
        << "(allow signal (target self))\n"
        << "(allow sysctl-read)\n"
        << "(allow mach-lookup)\n"
        << "(allow network-outbound)\n"
        << "(deny network-inbound)\n"
        << "(deny process-exec*)\n"
        << "(allow file-read*"
        << " (subpath \"/System\")"
        << " (subpath \"/usr\")"
        << " (subpath \"/bin\")"
        << " (subpath \"/sbin\")"
        << " (subpath \"/Library\")"
        << " (subpath \"/etc\")"
        << " (subpath \"/private/etc\")"
        << " (subpath \"/dev\")"
        << " (subpath \"/private/var/db\")"
        << " (subpath \"/var/db\")"
        << " (subpath \"" << app << "\")"
        << " (subpath \"" << configDir << "\"))\n"
        << "(allow file-map-executable"
        << " (subpath \"/System\")"
        << " (subpath \"/usr\")"
        << " (subpath \"/Library\")"
        << " (subpath \"" << app << "\"))\n"
        << "(allow file-write*"
        << " (subpath \"" << app << "\")"
        << " (subpath \"" << configDir << "\")"
        << " (literal \"/dev/null\")"
        << " (literal \"/dev/tty\"))\n";

    char* errorBuffer = nullptr;
    if (::sandbox_init(profile.str().c_str(), 0, &errorBuffer) != 0)
    {
        err = errorBuffer ? errorBuffer : "sandbox_init failed";
        if (errorBuffer)
            ::sandbox_free_error(errorBuffer);
        return false;
    }
    return true;
}
#endif

#if defined(_WIN32)
bool applyWindows(const SandboxOptions& options, std::string& err)
{
    (void)options;
    bool applied = false;

    static HANDLE job = nullptr;
    job = ::CreateJobObjectA(nullptr, nullptr);
    if (job)
    {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION info{};
        info.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_ACTIVE_PROCESS |
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
            JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
        info.BasicLimitInformation.ActiveProcessLimit = 1;
        if (::SetInformationJobObject(job, JobObjectExtendedLimitInformation,
                                      &info, sizeof(info)))
        {
            JOBOBJECT_BASIC_UI_RESTRICTIONS ui{};
            ui.UIRestrictionsClass =
                JOB_OBJECT_UILIMIT_HANDLES |
                JOB_OBJECT_UILIMIT_READCLIPBOARD |
                JOB_OBJECT_UILIMIT_WRITECLIPBOARD |
                JOB_OBJECT_UILIMIT_GLOBALATOMS |
                JOB_OBJECT_UILIMIT_DESKTOP |
                JOB_OBJECT_UILIMIT_DISPLAYSETTINGS |
                JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS |
                JOB_OBJECT_UILIMIT_EXITWINDOWS;
            ::SetInformationJobObject(job, JobObjectBasicUIRestrictions, &ui,
                                      sizeof(ui));
            if (::AssignProcessToJobObject(job, ::GetCurrentProcess()))
                applied = true;
        }
    }

    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dynamicCode{};
    dynamicCode.ProhibitDynamicCode = 1;
    if (::SetProcessMitigationPolicy(ProcessDynamicCodePolicy, &dynamicCode,
                                     sizeof(dynamicCode)))
        applied = true;

    PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY extensionPoints{};
    extensionPoints.DisableExtensionPoints = 1;
    ::SetProcessMitigationPolicy(ProcessExtensionPointDisablePolicy,
                                 &extensionPoints, sizeof(extensionPoints));

    PROCESS_MITIGATION_IMAGE_LOAD_POLICY imageLoad{};
    imageLoad.NoRemoteImages = 1;
    imageLoad.NoLowMandatoryLabelImages = 1;
    if (::SetProcessMitigationPolicy(ProcessImageLoadPolicy, &imageLoad,
                                     sizeof(imageLoad)))
        applied = true;

    PROCESS_MITIGATION_FONT_DISABLE_POLICY fonts{};
    fonts.DisableNonSystemFonts = 1;
    ::SetProcessMitigationPolicy(ProcessFontDisablePolicy, &fonts, sizeof(fonts));

    if (!applied)
    {
        err = "no Windows sandbox/mitigation policy could be applied";
        return false;
    }
    return true;
}
#endif

} // namespace

const char* sandboxPlatformName()
{
#if defined(__linux__)
    return "Linux (Landlock + seccomp)";
#elif defined(__OpenBSD__)
    return "OpenBSD (unveil + pledge)";
#elif defined(__APPLE__)
    return "macOS (sandbox_init)";
#elif defined(_WIN32)
    return "Windows (job object + mitigations)";
#elif defined(__FreeBSD__)
    return "FreeBSD (not implemented)";
#else
    return "unsupported platform";
#endif
}

bool sandboxApply(const SandboxOptions& options, std::string& err)
{
    if (!options.enabled)
        return true;

#if defined(__linux__)
    return applyLinux(options, err);
#elif defined(__OpenBSD__)
    return applyOpenBSD(options, err);
#elif defined(__APPLE__)
    return applyMacOS(options, err);
#elif defined(_WIN32)
    return applyWindows(options, err);
#else
    (void)options;
    err = std::string("sandbox is not implemented on ") + sandboxPlatformName();
    return false;
#endif
}

} // namespace TriMessage
