# TriMessage / Trigande — использование

Клиент и relay-сервер для чата поверх I2P (SAM). Один бинарник `Trie` умеет
работать и клиентом, и сервером.

---

## 1. Сборка

```bash
make Trie
```

Бинарник: `./Trie`.

Что нужно:

- `g++` с C++17;
- `libgmp` / `libgmpxx` (`-lgmp -lgmpxx`);
- собранная библиотека `i2psam` (`make -C i2psam`, цель `prepareSAM` делает это
  автоматически);
- запущенный SAM-бридж I2P (по умолчанию `127.0.0.1:7656`).

`Makefile` собирает `Trie` из `tri.cpp`, файлов `src/`, а также **существующих**
`trigande.cpp`, `alberthofman.cpp` и `ChaCha20.cpp`. Реализации тригонометрии и
Diffie-Hellman не дублируются.

Поддерживаемые платформы:

- **Linux** — основная цель, sandbox на Landlock + seccomp;
- **OpenBSD** — sandbox на unveil + pledge. Нужен `gmake` (`pkg_add gmp
  gmpxx gmake`), потому что системный `make` не понимает GNU-условия;
  `ksh make_openbsd.sh` уже вызывает `gmake`;
- **Windows / macOS** — собираются, но при компиляции и запуске печатается
  предупреждение: полноценной изоляции там нет, использовать только для
  тестов. Для Windows нужен MSYS2/MinGW-w64 и `gmp`, для macOS — Homebrew
  `gmp` (`make Trie` с `CXXFLAGS`/`LIBS` из `brew --prefix gmp`).

### Статическая сборка для Windows

Windows-сборки не должны требовать установленных отдельно `libgmp`,
`libstdc++`, `libgcc` или `libwinpthread`. В репозитории есть два Makefile:

```bash
make -f Makefile.mingw64     # x86_64, полностью статический Trie.exe
make -f Makefile.mingw32     # i686,   полностью статический Trie.exe
```

Обе цели передают линкеру `-static -static-libgcc -static-libstdc++`.
GMP тоже линкуется статически. Если GMP собран отдельно, укажите префикс:

```bash
make -f Makefile.mingw64 GMP_PREFIX=/opt/gmp-x86_64
make -f Makefile.mingw32 GMP_PREFIX=/opt/gmp-i686
```

В MSYS2 достаточно поставить `mingw-w64-x86_64-gcc` +
`mingw-w64-x86_64-gmp` (или `i686`-варианты). Проверить импорт можно так:

```bash
objdump -p Trie.exe | grep 'DLL Name'
```

В списке должны быть только системные DLL Windows (`KERNEL32`, `msvcrt`,
`WS2_32`, `bcrypt`). Если появились `libgmp`, `libstdc++`, `libgcc` или
`libwinpthread` — сборка не статическая.

---

## 2. Быстрый старт (клиент)

```bash
./Trie
```

При первом запуске рядом с бинарником создаётся `trigande.conf`:

- если в нём нет `private_key`, ключ генерируется через SAM и сохраняется;
- создаётся ник и имя SAM-сессии;
- файл получает права `0600`;
- если есть терминал, программа предлагает задать пароль и шифрует конфиг
  (рекомендуется). Пустой пароль оставляет файл открытым.

Пароль можно задать и без вопроса:

```bash
./Trie --config-password 'мой пароль'
TRIGANDE_CONFIG_PASSWORD='мой пароль' ./Trie
```

`--no-config-password` явно оставляет конфиг в plaintext. Пароль шифрования
файла — **не** пароль relay-чата (`--password` / `relay_password`).

В консоли появятся destination и fingerprint. Команда:

```
/getMyPubKey
```

печатает ваш полный I2P destination. Его нужно передать второму участнику,
который подключается так:

```
/connect <полный destination>
```

Полный destination — это длинная base64-строка (не имя из addressbook).
Можно вставлять и приватную форму, напечатанную `/getMyPubKey`: клиент сам
отрежет приватную часть.

Дальше:

```
/users
/chat 1
привет
```

Строка без `/` уходит в активный чат.

---

## 3. Опции командной строки

```text
./Trie [опции]
```

### Клиент

| Опция | Что делает |
|---|---|
| `-H, --host <host>` | адрес SAM-бриджа (по умолчанию `127.0.0.1`) |
| `-P, --port <port>` | порт SAM (по умолчанию `7656`) |
| `-n, --nick <name>` | ник |
| `-k, --priv <destination>` | использовать готовый приватный destination |
| `-s, --session <name>` | имя SAM-сессии |

### Relay-сервер

| Опция | Что делает |
|---|---|
| `-S, --server` | запустить relay-сервер |
| `-D, --daemon` | уйти в фон, писать лог в `trigande.log` рядом с бинарником |
| `--relay-version <2\|3>` | версия relay: `2` — шифрование, `3` — без шифрования |
| `--relay-limit <n>` | максимум участников |
| `--anonymous` | скрывать настоящие fingerprint участников |
| `--no-ask-plain` | не спрашивать подтверждение при входе на relay версии 3 |

### Криптография

| Опция | Что делает |
|---|---|
| `--dh-bits <n>` | размер группы DH (по умолчанию `1024`) |
| `--group-bits <n>` | размер генератора `g` (по умолчанию `128`) |
| `--secret-bits <n>` | размер личного показателя DH (по умолчанию `256`) |
| `--max-peer-dh-bits <n>` | предупреждать, если у пира DH больше этого (по умолчанию `8192`) |
| `--allow-huge-dh` | принимать огромные DH-ключи без вопроса |

### Приём соединений и анти-флуд

| Опция | Что делает |
|---|---|
| `--auto-accept` | автоматически принимать входящих пиров |
| `--no-auto-accept` | входящий пир ждёт `/accept` (по умолчанию) |
| `--wait-accept-time <s>` | сколько секунд ждать `/accept` (по умолчанию `45`) |
| `--flood-window <s>` | окно подсчёта флуда (по умолчанию `10`) |
| `--flood-repeat <n>` | повторов одного текста до кика (по умолчанию `6`) |
| `--flood-garbage <n>` | мусорных кадров до кика (по умолчанию `8`) |
| `--flood-dh <n>` | DH-запросов за окно до кика (по умолчанию `4`) |
| `--flood-messages <n>` | сообщений за окно до кика (по умолчанию `30`) |
| `--ban-initial <s>` | первый бан в секундах (по умолчанию `60`) |
| `--ban-max <s>` | максимальный бан в секундах (по умолчанию `86400`) |
| `--ban-memory <mb>` | лимит памяти под баны (по умолчанию `4`) |
| `--no-color` | отключить ANSI-цвета |

`0` в `--flood-repeat`, `--flood-garbage`, `--flood-dh` или
`--flood-messages` отключает соответствующую проверку. Обычная быстрая
переписка (например, 10 сообщений подряд) не банится: предупреждение
появляется только на 75% лимита, а кик — при превышении лимита.

### Прочее

| Опция | Что делает |
|---|---|
| `-c, --config <path>` | путь к конфигу |
| `--config-password <p>` | пароль, которым шифруется конфиг |
| `--no-config-password` | не шифровать конфиг (plaintext) |
| `--no-sandbox` | отключить локальную изоляцию **только на этот запуск** |
| `-h, --help` | справка |

**Важно:** почти все опции не только применяются на этот запуск, но и
записываются в конфиг. То есть `./Trie -H 10.0.0.5 -P 7657` сохранит новый
адрес SAM. Исключения: `--config-password`, `--no-config-password` и
`--no-sandbox` действуют только на текущий процесс, чтобы отладочный запуск
не отключал sandbox навсегда.

---

## 4. Конфиг

По умолчанию: `trigande.conf` рядом с бинарником. Другой путь:
`./Trie -c /path/to/file.conf`.

Формат — `key = value`, `#` — комментарий. Неизвестные ключи игнорируются.
Запись атомарная: сначала `*.tmp`, потом `rename`, права `0600`.

Если задан пароль, файл целиком шифруется:

```text
TRIGANDE-ENCRYPTED-CONFIG-V1
version = 1
kdf = pbkdf2-hmac-sha256
iterations = 210000
salt = <base64>
nonce = <base64>
hmac = <base64>
data = <base64>
```

Используются PBKDF2-HMAC-SHA256 (210000 итераций), ChaCha20 и HMAC-SHA256 для
проверки целостности. Неверный пароль даёт `wrong config password or damaged
config`. Пароль нигде в файле не хранится.

При запуске с зашифрованным конфигом программа спрашивает пароль, берёт его из
`TRIGANDE_CONFIG_PASSWORD` или из `--config-password`. Если терминала нет и
пароль не передан — запуск завершается ошибкой.

| Ключ | Смысл |
|---|---|
| `nick` | ник |
| `private_key` | приватный I2P destination (полный, с приватными ключами) |
| `sam_host` | хост SAM |
| `sam_port` | порт SAM |
| `sam_session` | имя SAM-сессии |
| `sam_signature_type` | тип подписи, если его нельзя определить по ключу |
| `dh_bits` | размер простого числа `p` для DH |
| `group_bits` | размер генератора `g` |
| `secret_bits` | размер своего секрета при установке соединения |
| `rekey_secret_bits` | размер секрета при плановой смене ключа |
| `max_peer_dh_bits` | порог предупреждения о большом DH у пира; `0` — не проверять |
| `allow_huge_dh` | `true` — не спрашивать про большой DH |
| `sandbox` | `true` — локальная изоляция процесса (по умолчанию) |
| `server_mode` | `true` — запускать relay |
| `daemon_mode` | `true` — уходить в фон (только для relay) |
| `relay_version` | `2` — шифрованный relay, `3` — открытый |
| `relay_limit` | максимум участников relay |
| `relay_anonymous` | `true` — подменять fingerprint участников |
| `relay_ask_plain` | `true` — спрашивать согласие перед relay v3 |
| `relay_password` | пароль группы relay (не путать с паролем шифрования файла) |
| `auto_accept` | `true` — принимать входящих без `/accept` (по умолчанию `false`) |
| `wait_accept_time_sec` | сколько секунд ждать подтверждения входящей заявки |
| `flood_window_sec` | окно анти-флуда в секундах |
| `flood_repeat_limit` | лимит повторов одного текста в окне |
| `flood_garbage_limit` | лимит мусорных кадров в окне |
| `flood_dh_limit` | лимит DH/REKEY-запросов в окне |
| `flood_message_limit` | лимит сообщений в окне |
| `ban_initial_seconds` | первый бан |
| `ban_max_seconds` | максимальный бан (по умолчанию сутки) |
| `ban_memory_limit_mb` | лимит памяти под таблицу банов; `0` — без лимита |
| `colors` | `true` — ANSI-цвета в терминале |
| `contact` | контакт в формате `ник|destination|base64(32-байтовый секрет)` |

Пример:

```ini
nick = alice
private_key = AAAAB...
sam_host = 127.0.0.1
sam_port = 7656
sam_session = TriMessage-alice-a1b2
sam_signature_type = DSA_SHA1

dh_bits = 1024
group_bits = 128
secret_bits = 256
rekey_secret_bits = 128

max_peer_dh_bits = 8192
allow_huge_dh = false

sandbox = true

server_mode = false
daemon_mode = false
relay_version = 2
relay_limit = 64
relay_anonymous = false
relay_ask_plain = true

auto_accept = false
wait_accept_time_sec = 45
flood_window_sec = 10
flood_repeat_limit = 6
flood_garbage_limit = 8
flood_dh_limit = 4
flood_message_limit = 30
ban_initial_seconds = 60
ban_max_seconds = 86400
ban_memory_limit_mb = 4
colors = true
```

`private_key` — это секрет. Не публикуйте файл и не передавайте его как
«destination»: для подключения нужен только публичный destination из
`/getMyPubKey`. Если конфиг не зашифрован, любой, кто прочитал файл, получает
ваш приватный ключ и пароль группы relay. Включите шифрование конфига.

### Локальная изоляция (sandbox)

По умолчанию `sandbox = true`. Если изоляцию не удалось установить, программа
**отказывается работать**: лучше явная ошибка, чем тихий запуск без защиты.
Отключить можно только осознанно:

```bash
./Trie --no-sandbox              # на один запуск
/settings sandbox false          # сохранить в конфиг (не рекомендуется)
```

Что делает sandbox:

- **Linux** — Landlock ограничивает файловую систему каталогом программы и
  конфигом; seccomp запрещает `execve`, `fork`, `ptrace`, `mount`, `bpf`,
  `io_uring`, загрузку модулей и другие опасные вызовы. Сеть остаётся
  доступной для SAM и I2P.
- **OpenBSD** — unveil даёт `rwc` только на файл конфига, `wc` на каталог
  программы (для `*.tmp` + `rename` и лога), плюс минимум для
  `/etc/hosts`, `/etc/resolv.conf`, `/dev/*`; pledge ограничивает системные
  вызовы. Системные каталоги вроде `/usr` не открываются: библиотеки уже
  загружены до установки sandbox.
- **macOS / Windows** — частичная изоляция. При сборке и запуске печатается
  предупреждение, что это небезопасно; для реальной работы используйте
  Linux или OpenBSD.

Sandbox устанавливается после `daemonize`, поэтому демон успевает открыть лог
и сменить каталог.

---

## 5. Команды клиента

| Команда | Что делает |
|---|---|
| `/help` | список команд |
| `/getMyPubKey` | показать свой destination и fingerprint |
| `/connect <destination>` | подключиться к пиру или relay |
| `/users` | список подключённых и участников relay |
| `/chat <id\|nick>` | выбрать активный чат и показать историю |
| `/msg [id\|nick] <text>` | отправить сообщение |
| `/ping [id\|nick\|destination]` | измерить задержку; без аргумента — всем |
| `/deluser <id\|nick>` | закрыть соединение с пользователем |
| `/accept <id\|all>` | принять входящую заявку |
| `/deny <id\|all>` | отклонить входящую заявку |
| `/ban <id\|nick\|destination\|fingerprint> [минуты]` | забанить вручную |
| `/banlist`, `/bans` | показать активные баны |
| `/delban <номер\|destination\|fingerprint\|all>` | снять бан |
| `/contacts [list]` | список контактов и их онлайн-статус |
| `/contacts add <id\|nick>` | добавить подключённого пира в контакты |
| `/contacts add <destination> [ник] [секрет]` | добавить контакт офлайн |
| `/contacts del <номер\|ник\|destination>` | удалить контакт |
| `/contacts connect <номер\|ник\|destination>` | подключиться к контакту |
| `/contacts connectall` | подключиться ко всем контактам |
| `/reidentity` | сменить Destination (после подтверждения контактами) |
| `/nick <name>` | сменить ник (сохраняется в конфиг) |
| `/rekey [id\|nick]` | принудительно сменить DH-ключ |
| `/settings [key value]` | показать или изменить настройки |
| `/decodeconf`, `/conf`, `/showconf` | показать расшифрованный конфиг, секреты — `(hidden)` |
| `/panic`, `/p` | разослать panic relay-пирам, стереть конфиг/секреты и выйти |
| `/status` | состояние узла, пиры, relay-roster |
| `/quit` | выход |

Алиасы: `/mykey`, `/list`, `/del`, `/kick`, `/removeuser`, `/set`, `/exit`, `/q`.

Строка без `/` отправляется в активный чат.

### `/settings`

Без аргументов показывает все настройки. Секреты (`private_key`,
`config_password`, `relay_password`) не печатаются, вместо них `(hidden)`.
С аргументами:

```
/settings nick bob
/settings max_peer_dh_bits 4096
/settings relay_limit 32
/settings sandbox false
/settings relay_password новый-пароль-группы
```

Управление ключом и паролем файла:

```
/settings private_key <полный приватный destination>
/settings private_key        # запросить ключ без эха
/settings private_key -      # удалить ключ, новый сгенерируется при старте
/settings config_password    # запросить новый пароль без эха и перешифровать
/settings config_password -  # отключить шифрование, файл станет plaintext
```

`private_key` проверяется: принимается только корректный приватный I2P
destination. После установки ключа нужен перезапуск. Старый ключ можно
вернуть таким образом в любой момент — файл для этого сначала расшифровывается
паролем при запуске.

Что применяется сразу:

- `nick`;
- `dh_bits`, `group_bits` — локальная группа пересоздаётся сразу;
- `max_peer_dh_bits`, `allow_huge_dh`;
- `auto_accept`, `wait_accept_time_sec`;
- `flood_window_sec`, `flood_repeat_limit`, `flood_garbage_limit`,
  `flood_dh_limit`, `flood_message_limit`;
- `ban_initial_seconds`, `ban_max_seconds`, `ban_memory_limit_mb`;
- `colors`.

Что требует перезапуска:

- `private_key`, `sam_host`, `sam_port`, `sam_session`, `sam_signature_type`;
- `sandbox`;
- `server_mode`, `daemon_mode`, `relay_version`, `relay_limit`,
  `relay_anonymous`, `relay_ask_plain`.

`secret_bits` и `rekey_secret_bits` сохраняются и применяются к следующим
рукопожатиям / смене ключа. `config_password` перешифровывает файл сразу.

### Контакты, приём соединений и баны

По умолчанию `auto_accept = false`. Входящий пир проходит DH-рукопожатие, но
не добавляется в чат, пока вы не выполните:

```text
/accept 3
/accept all
/deny 3
```

Заявка живёт `wait_accept_time_sec` секунд (по умолчанию 45), затем
отклоняется автоматически. Одновременно хранится не больше 32 заявок.
Контакты с верным секретом принимаются сразу и не требуют `/accept`.

Анти-флуд считает события в окне `flood_window_sec` отдельно для каждого пира:

- сообщения — `/flood-messages`, по умолчанию 30 за 10 секунд;
- одинаковый текст — `/flood-repeat`, по умолчанию 6 повторов;
- мусорные/неизвестные кадры — `/flood-garbage`, по умолчанию 8;
- DH/REKEY-запросы — `/flood-dh`, по умолчанию 4.

На 75% лимита сообщений выводится предупреждение. При превышении лимита пир
кикается и банится. Если лимит превышают сразу несколько пиров, они кикаются
все. Короткая нормальная переписка (10 сообщений подряд) под это не попадает.

Бан начинается с `ban_initial_seconds` (60 секунд) и удваивается при каждом
новом нарушении: 1, 2, 4, 8 минут… до `ban_max_seconds` (24 часа). Вручную:

```text
/ban 2                 # забанить подключённого пользователя #2
/ban <destination> 30  # забанить на 30 минут
/banlist               # список банов
/delban 1              # снять первый бан
/delban all
```

Таблица банов ограничена `ban_memory_limit_mb`. Когда лимит достигнут,
автоматические баны прекращаются, клиент на 5 минут перестаёт отвечать
незнакомым пирам и предупреждает, что идёт целенаправленная атака и лучше
сменить Destination через `/reidentity`.

Контакты хранят ник, полный Destination и 32-байтовый секрет. Секрет
доказывает личность при рукопожатии. Добавление подключённого пира:

```text
/contacts add 2
```

Он получит секрет по шифрованному каналу и сохранит вас как контакт.
Добавление офлайн-контакта:

```text
/contacts add <destination> alice <base64-или-hex-секрет>
```

Без секрета он будет сгенерирован и показан — передайте его контакту другим
каналом. Если контакт подключается с новым Destination, но присылает верный
секрет, клиент предупреждает и обновляет Destination контакта против
подмены. Без секрета или с неверным секретом соединение отклоняется.

`/reidentity` генерирует новую пару ключей, отправляет новый Destination всем
онлайн-контактам и ждёт до 60 секунд подтверждения от каждого. Только после
этого новый приватный ключ сохраняется в конфиг, клиент завершается. Запустите
его снова и подключите контакты вручную:

```text
/contacts connectall
```

Если подтвердили не все, старый ключ остаётся, а новый стирается из памяти.

### `/decodeconf`

Показывает настройки из уже расшифрованного конфига. Это удобно, когда файл
зашифрован и его нельзя просто открыть редактором. Секреты скрыты:

```
private_key = (set, hidden)
config_password = (set, hidden)
relay_password = (set, hidden)
```

### `/panic` и `/p`

Аварийный выход:

1. relay-пирам отправляется `USER IS PANICKED [BYE...]`;
2. обычным direct-пирам panic не отправляется;
3. соединения закрываются, ключи и буферы затираются;
4. файл конфига перезаписывается случайными байтами и удаляется;
5. процесс завершается.

Используйте, если нужно срочно убрать ключи с диска. Восстановить конфиг после
этого нельзя.

---

## 6. Relay-сервер

### Запуск

```bash
# шифрованный relay, до 32 участников
./Trie -S --relay-version 2 --relay-limit 32

# открытый relay с анонимными fingerprint, в фоне
./Trie -S --relay-version 3 --anonymous -D
```

Сервер печатает свой destination и fingerprint. Клиенты подключаются к нему
через `/connect <destination>`.

### Версия 2 — шифрование

- при входе участника сервер проводит с ним DH-обмен;
- у каждого участника **свой** ключ;
- сервер расшифровывает сообщение и заново шифрует его каждому получателю;
- размер секрета участника: `secret_bits - 32`, но не меньше 64;
- плановая смена ключей (`REKEY`) для relay-соединений отключена.

### Версия 3 — без шифрования

- DH не выполняется, сообщения идут в base64-обёртке без шифрования;
- клиент при подключении показывает предупреждение и спрашивает согласие;
- отключить вопрос: `--no-ask-plain` или `relay_ask_plain = false`;
- relay и любой, кто видит трафик, читает сообщения.

### Список участников

Сервер рассылает всем сообщение `USERS` в формате:

```
id:nick:fingerprint;id:nick:fingerprint;...
```

Клиент показывает его в `/users` и `/status`. В режиме `--anonymous` вместо
настоящего fingerprint показывается треугольное число:

```
T(n) = 1 + 2 + ... + n
```

Оно записывается в 16 байт с переносом, начиная с младшего байта. Настоящий
fingerprint остаётся только на сервере.

### Ограничения

- `relay_limit` проверяется при входе; при переполнении сервер отвечает
  `HELLO_REJECT relay is full`;
- сообщение чата — не больше 4000 байт;
- молчащий участник удаляется через 35 секунд;
- relay также отклоняет слишком большой DH у входящего, если не включён
  `allow_huge_dh`.

### Демон

`-D` (или `daemon_mode = true`) работает только вместе с `-S`. Лог пишется в
`trigande.log` рядом с бинарником. Корректное завершение — `SIGINT`/`SIGTERM`:
участники получают `BYE`.

---

## 7. Как устроен протокол

### Рукопожатие

1. Клиент отправляет `HELLO <base64>`.
2. Сервер отвечает `HELLO_ACK <base64>` или `HELLO_REJECT <причина>`.
3. Обе стороны считают общий DH-секрет.
4. Клиент отправляет `AUTH <proof>`, сервер проверяет.
5. Сервер отправляет свой `AUTH <proof>`, клиент проверяет.
6. Клиент подтверждает `AUTH_OK`.

В `HELLO` лежат: версия `TRI-HS/2`, ник, destination, fingerprint, `p`, `g`,
DH-публичный ключ, случайный challenge, версия relay (`0` — прямой пир,
`2` — шифрованный relay, `3` — открытый relay) и роль.

`proof` — это ChaCha20 по транскрипту (ник, destination, оба challenge, версии,
роли), ключ — из DH, nonce зависит от роли и транскрипта. Сравнение
constant-time.

### Ключ из DH

`deriveKey` берёт **все** байты общего секрета, а не только первые 32:

1. `mpz` переводится в байты;
2. маленький sponge поглощает все байты с позиционно-зависимыми сдвигами;
3. отдельные домены для ключа и IV;
4. 48 байт дополнительно «отбеливаются» ChaCha20;
5. получаются `key[32]` и `iv[16]`.

Результат детерминированный: одинаковый DH-секрет даёт одинаковые key/IV.

### Кадр сообщения (версия 2)

До base64:

```
version(1) | salt(12) | padLen(4) | padding(padLen) | cipherLen(4) | ciphertext
```

- `version = 2`;
- nonce для ChaCha20 = `salt XOR iv`;
- `padding` — случайная длина до 768 байт, генерируется через
  `Triangle::sin_deg/cos_deg` из `trigande.cpp`;
- при расшифровке padding пропускается, проверяется magic `TRI2`;
- base64-строка передаётся в строке `MSG ...`.

Для relay v3 используется тот же конверт `TRI2`, но без шифрования
(`encodePlain`/`decodePlain`).

### Внутренний конверт

```
TRI2 \x1f type \x1f fromFp \x1f fromNick \x1f text
```

Типы: `CHAT`, `PING`, `PONG`, `USERS`, `SERVER`.

### Смена ключей

- каждые 5–15 минут (случайно);
- инициатор — сторона с лексикографически меньшим fingerprint;
- обмен `REKEY` → `REKEY_ACK` → `REKEY_DONE`;
- для relay и открытых соединений недоступна;
- вручную: `/rekey`.

### Таймауты

- нет данных 10 секунд — отправить `PING`;
- нет данных 35 секунд — разорвать соединение;
- relay проверяет молчащих каждые 5 секунд;
- история на пир — 100 строк.

---

## 8. Большой DH у пира

При исходящем подключении клиент сравнивает размер `p` и публичного DH-ключа
пира с `max_peer_dh_bits`. Если больше:

- при `allow_huge_dh = true` — продолжает молча;
- иначе спрашивает подтверждение в консоли;
- при отказе отправляет `BYE`.

При входящем подключении вопрос не задаётся (чтобы нельзя было подвесить клиент
дорогой проверкой): соединение отклоняется, пока в конфиге не включён
`allow_huge_dh`.

Relay-сервер делает такую же проверку для входящих участников.

---

## 9. Что за что отвечает

### Корень

| Файл | Ответственность |
|---|---|
| `tri.cpp` | точка входа: `getopt_long`, загрузка/создание конфига, генерация ключа, `daemonize`, обработка сигналов, выбор клиент/сервер |
| `trigande.h`, `trigande.cpp` | **существующая** реализация `Triangle::sin_deg`, `cos_deg`, `sin_rads`, `cos_rads`. Используется для padding в кадрах; не переписана |
| `alberthofman.h`, `alberthofman.cpp` | **существующая** реализация `DiffiHofman` (`random_n`, `getPublicKey`, `getSharedKey`). Используется клиентом, пирами и relay; не переписана |
| `ChaCha20.h`, `ChaCha20.cpp` | потоковый шифр ChaCha20 (ключ, nonce, шифрование/расшифрование) |
| `i2psam/` | библиотека SAM: сессии, сокеты, `STREAM CONNECT/ACCEPT`, `DEST GENERATE` |
| `test.cpp` | старый тест `trigande.cpp` (цель `make Test`) |
| `Makefile` | цели `Trie`, `Test`, `lTrigande`, `lHofman`, `prepareSAM`, `clean` |
| `README.md` | краткое описание проекта |
| `assets/` | ресурсы репозитория |
| `usage.md` | этот файл |
| `PROMPT` | исходное задание |

Генерируются во время работы: `Trie` (бинарник), `trigande.conf` (конфиг),
`trigande.log` (лог демона), `*.o` / `lib*.so` (промежуточные файлы сборки).

### `src/`

| Файл | Ответственность |
|---|---|
| `src/config.h/.cpp` | структура `Config`, значения по умолчанию, путь к конфигу, парсинг, валидация, шифрование PBKDF2/ChaCha20/HMAC, атомарное сохранение `0600` |
| `src/common/protocol.h` | константы таймаутов, лимитов, heartbeat, истории |
| `src/common/platform.h/.cpp` | переносимый слой: пути к бинарнику, `chdir`, TTY/пароль без эха, OS CSPRNG, безопасное затирание и удаление, атомарная замена файла |
| `src/common/hash.h/.cpp` | SHA-256, HMAC-SHA256, PBKDF2-HMAC-SHA256 для шифрования конфига (без OpenSSL) |
| `src/common/util.h/.cpp` | RNG, время, hex/base64, I2P-base64, fingerprint, анонимный fingerprint, нормализация destination, разбор приватного destination, пути, `askYesNo` |
| `src/common/crypto.h/.cpp` | `mpzToBytes`, `deriveKey` (32-байтный ключ + 16-байтный IV), `makeProof`, nonce из строки |
| `src/common/frame.h/.cpp` | кадр версии 2, padding через `trigande.cpp`, шифрование/расшифрование, plaintext-конверт `TRI2`, `makePlain`/`parsePlain` |
| `src/common/handshake.h/.cpp` | `HELLO`/`HELLO_ACK`, поля `HsData`, кодирование/декодирование, транскрипт для `AUTH` |
| `src/security/sandbox.h/.cpp` | локальная изоляция: Landlock+seccomp (Linux), unveil+pledge (OpenBSD), sandbox_init (macOS), job object + mitigations (Windows) |
| `src/client/client.h/.cpp` | жизненный цикл клиента: SAM-сессия, приём и установка соединений, таблица команд, `/settings`, `/decodeconf`, `/panic`, relay-roster, цикл ping/rekey |
| `src/client/peer.h/.cpp` | одно соединение: сокет, отправка/приём кадров, ключи, ping/pong, `REKEY`, история сообщений, `wipeSecrets()` |
| `src/server/relay.h/.cpp` | relay-сервер: приём участников, DH на участника, рассылка ростера, пересылка чата, анонимизация, лимит, janitor, демон-лог |

### Поток данных

```text
tri.cpp
  └─ Config (src/config)
       ├─ Client (src/client/client)
       │    ├─ Peer (src/client/peer) ── frame/crypto ── ChaCha20
       │    │        └─ DiffiHofman (alberthofman.cpp)
       │    └─ handshake (src/common/handshake)
       │         └─ deriveKey (src/common/crypto)
       └─ RelayServer (src/server/relay)
            ├─ DiffiHofman (alberthofman.cpp)
            ├─ frame/plain (src/common/frame)
            └─ util (fingerprint, roster, лимиты)
```

Общие вещи (конфиг, util, crypto, frame, handshake) вынесены в `src/common` и
`src/config.*`; клиентская и серверная логика не дублируют друг друга.

---

## 10. Частые проблемы

**`Can't init SAM stream session`** — SAM не запущен или неверные `sam_host` /
`sam_port`. Проверьте I2P и порт `7656`.

**`/connect` пишет, что нужен полный destination** — используйте строку из
`/getMyPubKey`, а не адрес из addressbook.

**`peer rejected the connection: DH key is too large`** — у пира
`dh_bits`/`secret_bits` больше вашего `max_peer_dh_bits`. Увеличьте лимит или
включите `allow_huge_dh`.

**Relay пишет `relay is full`** — достигнут `relay_limit`. Увеличьте его и
перезапустите relay.

**Клиент не подключается к relay v3 без вопроса** — так и задумано; вопрос
отключается через `--no-ask-plain`, но тогда вы принимаете риск открытого
трафика.

**Не создаётся ключ** — SAM недоступен. Для relay ключ обязателен: запустите
SAM и повторите запуск. Для клиента без ключа сессия будет временной, но
destination может быть непригоден для `/connect`.

**`config is encrypted; password is required` / `wrong config password`** —
задайте `TRIGANDE_CONFIG_PASSWORD`, `--config-password` или введите пароль в
терминале. Пароль relay-чата здесь не подходит.

**`sandbox failed` / `refusing to run without isolation`** — ядро не
поддерживает Landlock/seccomp или sandbox-профиль macOS не собрался. На Linux
проверьте ядро (Landlock с 5.13), на OpenBSD — версию. Для отладки можно
запустить с `--no-sandbox`, но это снимает защиту.

**`Can't init SAM stream session` после убийства клиента** — i2pd иногда
держит старую SAM-сессию несколько секунд. Подождите или перезапустите i2pd.

**Windows/macOS** — сборка работает, но при компиляции и запуске печатается
жирное предупреждение: изоляция там частичная. Не используйте эти сборки для
чувствительных ключей.
