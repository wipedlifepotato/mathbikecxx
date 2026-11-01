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

---

## 2. Быстрый старт (клиент)

```bash
./Trie
```

При первом запуске рядом с бинарником создаётся `trigande.conf`:

- если в нём нет `private_key`, ключ генерируется через SAM и сохраняется;
- создаётся ник и имя SAM-сессии;
- файл получает права `0600`.

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

### Прочее

| Опция | Что делает |
|---|---|
| `-c, --config <path>` | путь к конфигу |
| `-h, --help` | справка |

**Важно:** все опции не только применяются на этот запуск, но и записываются
в конфиг. То есть `./Trie -H 10.0.0.5 -P 7657` сохранит новый адрес SAM.

---

## 4. Конфиг

По умолчанию: `trigande.conf` рядом с бинарником. Другой путь:
`./Trie -c /path/to/file.conf`.

Формат — `key = value`, `#` — комментарий. Неизвестные ключи игнорируются.
Запись атомарная: сначала `*.tmp`, потом `rename`, права `0600`.

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
| `server_mode` | `true` — запускать relay |
| `daemon_mode` | `true` — уходить в фон (только для relay) |
| `relay_version` | `2` — шифрованный relay, `3` — открытый |
| `relay_limit` | максимум участников relay |
| `relay_anonymous` | `true` — подменять fingerprint участников |
| `relay_ask_plain` | `true` — спрашивать согласие перед relay v3 |

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

server_mode = false
daemon_mode = false
relay_version = 2
relay_limit = 64
relay_anonymous = false
relay_ask_plain = true
```

`private_key` — это секрет. Не публикуйте файл и не передавайте его как
«destination»: для подключения нужен только публичный destination из
`/getMyPubKey`.

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
| `/nick <name>` | сменить ник (сохраняется в конфиг) |
| `/rekey [id\|nick]` | принудительно сменить DH-ключ |
| `/settings [key value]` | показать или изменить настройки |
| `/status` | состояние узла, пиры, relay-roster |
| `/quit` | выход |

Алиасы: `/mykey`, `/list`, `/del`, `/kick`, `/removeuser`, `/set`, `/exit`, `/q`.

Строка без `/` отправляется в активный чат.

### `/settings`

Без аргументов показывает все настройки (приватный ключ скрыт). С аргументами:

```
/settings nick bob
/settings max_peer_dh_bits 4096
/settings relay_limit 32
```

Что применяется сразу:

- `nick`;
- `dh_bits`, `group_bits` — локальная группа пересоздаётся сразу;
- `max_peer_dh_bits`, `allow_huge_dh`.

Что требует перезапуска:

- `sam_host`, `sam_port`, `sam_session`, `sam_signature_type`;
- `server_mode`, `daemon_mode`, `relay_version`, `relay_limit`,
  `relay_anonymous`, `relay_ask_plain`.

`secret_bits` и `rekey_secret_bits` сохраняются и применяются к следующим
рукопожатиям / смене ключа. `private_key` через `/settings` изменить нельзя —
для нового ключа удалите конфиг.

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
| `src/config.h/.cpp` | структура `Config`, значения по умолчанию, путь к конфигу, парсинг, валидация, атомарное сохранение `0600` |
| `src/common/protocol.h` | константы таймаутов, лимитов, heartbeat, истории |
| `src/common/util.h/.cpp` | RNG, время, hex/base64, I2P-base64, fingerprint, анонимный fingerprint, нормализация destination, разбор приватного destination, пути, `askYesNo` |
| `src/common/crypto.h/.cpp` | `mpzToBytes`, `deriveKey` (32-байтный ключ + 16-байтный IV), `makeProof`, nonce из строки |
| `src/common/frame.h/.cpp` | кадр версии 2, padding через `trigande.cpp`, шифрование/расшифрование, plaintext-конверт `TRI2`, `makePlain`/`parsePlain` |
| `src/common/handshake.h/.cpp` | `HELLO`/`HELLO_ACK`, поля `HsData`, кодирование/декодирование, транскрипт для `AUTH` |
| `src/client/client.h/.cpp` | жизненный цикл клиента: SAM-сессия, приём и установка соединений, таблица команд, `/settings`, relay-roster, цикл ping/rekey |
| `src/client/peer.h/.cpp` | одно соединение: сокет, отправка/приём кадров, ключи, ping/pong, `REKEY`, история сообщений |
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
