/*
 * Local process isolation.
 *
 * The program never executes remote code and never shells out, but a real
 * sandbox adds defence in depth: it denies process execution, restricts file
 * access to the install/config directory and stops the process from spawning
 * children.  Linux uses Landlock+seccomp, OpenBSD uses unveil+pledge, macOS
 * uses sandbox_init and Windows uses a job object plus process mitigations.
 *
 * `--no-sandbox` / `sandbox = false` disables it explicitly.
 */
#pragma once

#include <string>

namespace TriMessage
{

struct SandboxOptions
{
    bool enabled = true;
    std::string appDir;
    std::string configPath;
};

/* Returns false when the platform sandbox could not be installed. */
bool sandboxApply(const SandboxOptions& options, std::string& err);

const char* sandboxPlatformName();

} // namespace TriMessage
