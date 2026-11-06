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
- Incoming connections can require approval (`/accept`, `/deny`), with
  configurable anti-flood limits, temporary bans and `/banlist` / `/delban`.
- Contacts are pinned to a Destination plus a 32-byte shared secret. A known
  contact appearing at a new Destination triggers a warning, and
  `/reidentity` moves you to a fresh Destination after all online contacts
  confirm.
- Nicknames are ASCII-only and validated at startup, on connect and on
  changes; control bytes in decrypted messages terminate the connection.
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
pkg_add gmp gmpxx gmake
ksh make_openbsd.sh
```

Windows (MSYS2/MinGW-w64) and macOS are also buildable, but are **not fully
isolated**; both the compiler and the program print a prominent warning. Use
Linux or OpenBSD for real work.

Static Windows binaries (no `libgmp`, `libstdc++`, `libgcc` or
`libwinpthread` needed on the target machine):

```bash
make -f Makefile.mingw64                      # x86_64
make -f Makefile.mingw32                      # i686
make -f Makefile.mingw64 GMP_PREFIX=/opt/gmp  # separately built static GMP
```

Both Makefiles pass `-static -static-libgcc -static-libstdc++` and link GMP
statically. CI builds both architectures and rejects the executable if
`objdump -p Trie.exe` reports any non-system DLL.

The binary is `./Trie`. The whole file format, CLI and commands are documented
in [usage.md](usage.md).

## Acceptance, anti-flood and contacts

Incoming peers need `/accept` unless `auto_accept = true` or the peer proves a
known contact secret. Pending requests expire after `wait_accept_time_sec`
(default 45 seconds):

```text
/accept 2
/deny 2
```

Repeated messages, repeated text, garbage frames and DH/REKEY bursts are
counted per peer in `flood_window_sec`. A warning is shown at 75% of the
message limit; exceeding any limit kicks and bans the peer. Bans start at one
minute, double on each repeat offence and stop at 24 hours:

```text
/ban 2
/ban <destination> 30
/banlist
/delban 1
```

`ban_memory_limit_mb` caps the ban table. When it is full, automatic bans stop
for five minutes, unknown peers are ignored, and the client suggests changing
your Destination with `/reidentity`.

Contacts keep a Destination and a 32-byte shared secret:

```text
/contacts add 2
/contacts add <destination> alice <secret>
/contacts
/contacts connectall
```

A contact connecting from a new Destination is accepted only with a valid
secret and the change is reported. `/reidentity` asks every online contact to
confirm a new Destination, then saves the new private key and exits; start the
client again and use `/contacts connectall`.

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
  program directory (for `*.tmp` + `rename` and the daemon log). Nothing else
  is unveiled: no `/etc`, `/dev` or `/usr`. Libraries are already loaded, the
  SAM host is a numeric IPv4 address, and randomness comes from `arc4random`
  instead of `/dev/urandom`. pledge is limited to
  `stdio rpath wpath cpath fattr inet`.

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
- Windows archives: fully static x86_64 and i686 `trigande.exe` (only Windows
  system DLLs are imported);
- macOS archive.

## Tested

- Linux
- Windows (On WINE with sandbox: (job object + mitigations))

## Screenshots

<img width="1918" height="918" alt="image" src="https://github.com/user-attachments/assets/0683b184-c290-48a3-a8de-41db3da62960" />

## Template

For the template used: [mathbikecxx](https://github.com/wipedlifepotato/mathbikecxx/tree/wmasterw).
