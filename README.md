# Trigande / TriMessage

Encrypted peer-to-peer and relay chat over I2P (SAM + ChaCha20).

- P2P chat with a DH key exchange and ChaCha20 message encryption.
- Group chat through a relay server.
- The relay password is sent as a proof during the handshake and is separate
  from the password that encrypts the config file.
- The config file (including the I2P private key) is encrypted at rest with
  PBKDF2-HMAC-SHA256 + ChaCha20 + HMAC-SHA256.
- Local process isolation: Landlock + seccomp on Linux, unveil + pledge on
  OpenBSD. It is enabled by default and can only be disabled explicitly.
- `/decodeconf`, `/settings`, and `/panic` for inspecting the decrypted
  config, editing keys/settings, and wiping everything in an emergency.
- Also includes a small `libtrigande` for sin/cos (`make lTrigande`,
  header `trigande.h`).

## Dependencies

- `libgmp` / `libgmpxx` (big numbers);
- a C++17 compiler (`g++` or `clang++`);
- a running SAM bridge (i2pd or Java I2P), default `127.0.0.1:7656`;
- the bundled `i2psam` submodule (`make prepareSAM`).

## Compilation

Linux:

```bash
make Trie
```

OpenBSD:

```sh
pkg_add gmp gmpxx
ksh make_openbsd.sh
```

Windows (MSYS2/MinGW-w64) and macOS are also buildable, but are **not fully
isolated**; both the compiler and the program print a prominent warning. Use
Linux or OpenBSD for real work.

The binary is `./Trie`. The whole file format, CLI and commands are documented
in [usage.md](usage.md).

## Config encryption

On the first run the program asks for a password (when a terminal is
available) and stores `trigande.conf` encrypted:

```text
TRIGANDE-ENCRYPTED-CONFIG-V1
version = 1
kdf = pbkdf2-hmac-sha256
iterations = 210000
salt = ...
nonce = ...
hmac = ...
data = ...
```

For scripted start:

```bash
./Trie --config-password 'secret'
TRIGANDE_CONFIG_PASSWORD='secret' ./Trie
```

`--no-config-password` keeps the file in plaintext. The config password is
**not** the relay chat password (`--password` / `relay_password`).

Inside the client:

```text
/decodeconf                  # show the decrypted config, secrets hidden
/settings config_password    # change the config password and re-encrypt
/settings private_key        # set an old I2P private key manually
/settings private_key -      # forget the key; generate a new one on start
```

## Sandbox

Enabled by default. If it cannot be installed, the program refuses to run.
For a single debugging run:

```bash
./Trie --no-sandbox
```

`--no-sandbox` is not persisted; use `/settings sandbox false` only if you
really want to disable it permanently.

- **Linux:** Landlock restricts filesystem access; seccomp blocks `execve`,
  `fork`, `ptrace`, `mount`, `bpf`, `io_uring`, module loading and similar
  calls. Networking stays available for SAM/I2P.
- **OpenBSD:** unveil gives `rwc` only to the config file and `wc` to the
  program directory (for `*.tmp` + `rename` and the daemon log), plus the
  minimal `/etc` and `/dev` paths. System directories are not unveiled because
  libraries are already loaded. pledge limits the syscall set.

## Panic

```text
/panic
/p
```

Sends `USER IS PANICKED [BYE...]` to relay peers (they forward it to the
room), closes connections, wipes keys and buffers, overwrites and removes the
config, and exits. Direct peers are not spammed because they do not see the
relay chat.

## CI / releases

GitHub Actions builds Linux, OpenBSD, Windows and macOS on every push and pull
request. A tag `v*` publishes:

- Linux binary, `.deb`, `.rpm`, AppImage;
- OpenBSD binary;
- Windows and macOS archives.

## Tested

- Linux
- OpenBSD

## Screenshots

<img width="1918" height="918" alt="image" src="https://github.com/user-attachments/assets/0683b184-c290-48a3-a8de-41db3da62960" />

## Template

For the template used: [mathbikecxx](https://github.com/wipedlifepotato/mathbikecxx/tree/wmasterw).
