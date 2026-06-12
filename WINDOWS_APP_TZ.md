# ТЗ: shadow-ssh для Windows

## 1. Цель

Создать Windows-приложение, аналогичное текущему Android-приложению `shadow-ssh`.

Приложение должно поднимать локальный сетевой туннель через SSH-сервер и проксировать трафик Windows-приложений, доменов или IP-адресов через этот туннель.

## 2. Технологический стек

- Desktop shell: Electron.
- Язык приложения: TypeScript.
- UI: Electron renderer + TypeScript.
- Main process: Electron main + TypeScript.
- Core networking libraries: собственные, без сторонних core proxy/VPN/tun2socks/SSH/VPN библиотек.
- Низкоуровневые библиотеки можно писать на любом подходящем языке:
  - Rust;
  - C++;
  - C;
  - Go;
  - TypeScript/Node native addon.
- Разрешено использовать:
  - системные Windows API;
  - системные криптографические API;
  - Electron и build tooling;
  - dev/build dependencies, не реализующие core tunnel/proxy логику.

Core tunnel/proxy/route logic должна быть собственной.

## 3. Основной функционал

### 3.1 SSH-конфигурации

Пользователь должен уметь:

- создавать SSH-конфигурацию;
- редактировать SSH-конфигурацию;
- удалять SSH-конфигурацию;
- выбирать активную SSH-конфигурацию.

Поля конфигурации:

- name;
- host;
- port;
- username;
- auth type:
  - password;
  - private key;
- password;
- private key id;
- private key passphrase;
- expected server fingerprint;
- keepalive interval;
- note.

### 3.2 SSH-ключи

Пользователь должен уметь:

- добавлять private key;
- редактировать имя ключа;
- удалять ключ;
- выбирать ключ в SSH-конфигурации.

Запрещено удалять SSH-ключ, если он используется хотя бы одной конфигурацией.

### 3.3 Подключение

Главный экран должен содержать:

- выбранную конфигурацию;
- статус подключения;
- кнопку Connect / Disconnect;
- кнопку Check tunnel;
- панель diagnostics;
- SSH terminal panel.

Состояния подключения:

- Disconnected;
- Connecting;
- Connected;
- Reconnecting;
- Disconnecting;
- Error.

При обрыве SSH-сессии приложение должно автоматически переподключаться до тех пор, пока пользователь явно не нажмёт Disconnect.

## 4. Routing mode

В Windows-версии вместо выбора Android-приложений нужно сделать отдельное окно выбора правил проксирования.

### 4.1 Типы правил

Пользователь должен уметь добавлять правила трёх типов:

- domain;
- ip;
- process.name.

### 4.2 Domain rules

Domain rule описывает домен или маску домена.

Примеры:

```text
youtube.com
*.youtube.com
googlevideo.com
*.googlevideo.com
```

Требования:

- поиск по списку правил;
- enable / disable rule;
- удаление правила;
- проверка валидности domain pattern;
- сохранение после перезапуска.

### 4.3 IP rules

IP rule описывает IP-адрес или CIDR range.

Примеры:

```text
8.8.8.8
1.1.1.1
142.250.0.0/15
2a00:1450::/32
```

Требования:

- поддержка IPv4;
- поддержка IPv6;
- поддержка CIDR;
- enable / disable rule;
- удаление правила;
- проверка валидности IP/CIDR;
- сохранение после перезапуска.

### 4.4 Process name rules

Process rule описывает имя процесса Windows.

Примеры:

```text
chrome.exe
msedge.exe
telegram.exe
discord.exe
```

Требования:

- список активных процессов;
- поиск по процессам;
- ручное добавление process name;
- enable / disable rule;
- удаление правила;
- сохранение после перезапуска.

### 4.5 Окно выбора правил

Окно routing rules должно содержать:

- tabs или segmented control:
  - Domains;
  - IPs;
  - Processes;
- общий поиск;
- список правил;
- кнопку Add;
- кнопку Import;
- кнопку Export;
- счётчик enabled rules;
- кнопку Save / Done.

Если нет enabled rules, приложение должно показать понятное предупреждение перед Connect.

## 5. Routing behavior

Приложение должно поддерживать два режима:

- Proxy all;
- Selected rules.

### 5.1 Proxy all

Весь поддерживаемый трафик устройства направляется через SSH-туннель.

### 5.2 Selected rules

Через SSH-туннель идёт только трафик, который соответствует enabled routing rules:

- домен совпал с domain rule;
- destination IP попал в IP/CIDR rule;
- процесс-источник совпал с process.name rule.

Если routing mode = `Selected rules` и нет enabled rules, подключение должно быть запрещено.

## 6. Сетевая архитектура Windows

Electron не должен напрямую выполнять низкоуровневую сетевую маршрутизацию.

Архитектура должна быть разделена:

```text
Electron UI
    |
    v
Electron main process
    |
    v
Local IPC
    |
    v
Windows privileged service
    |
    v
Custom networking core
    |
    v
Protected SSH connection
    |
    v
SSH server
    |
    v
Target sites/services
```

### 6.1 Windows service

Нужно реализовать отдельный privileged service.

Задачи service:

- управлять сетевым routing layer;
- открывать и защищать SSH-соединение;
- применять routing rules;
- отдавать статус в Electron app через local IPC;
- принимать команды Connect / Disconnect;
- писать diagnostics;
- выполнять reconnect.

### 6.2 IPC

Electron main process должен общаться с service через local IPC.

Требования:

- команды:
  - connect;
  - disconnect;
  - get status;
  - update config;
  - update routing rules;
  - check tunnel;
  - open terminal;
  - terminal input;
- события:
  - status changed;
  - diagnostics appended;
  - tunnel check result;
  - terminal output;
  - error.

IPC должен быть локальным и недоступным из сети.

## 7. SSH tunnel

SSH-клиент должен поддерживать:

- password auth;
- private key auth;
- passphrase private key;
- server fingerprint check;
- keepalive;
- reconnect;
- direct TCP forwarding;
- interactive shell channel для terminal.

Core SSH implementation должна быть собственной, если не будет отдельно согласовано использование внешнего SSH-клиента.

## 8. Diagnostics

Diagnostics должны быть доступны в UI под спойлером.

Требования:

- по умолчанию logs скрыты;
- настройка показа logs сохраняется;
- кнопка Copy logs;
- логи не ограничены фиксированными 80 строками в рамках текущего подключения;
- logs сбрасываются при новом пользовательском Connect.

Логировать можно:

- lifecycle подключения;
- выбранную конфигурацию без секретов;
- auth type;
- SSH server fingerprint;
- routing mode;
- количество enabled rules;
- reconnect attempts;
- tunnel check result;
- terminal lifecycle.

Запрещено логировать:

- password;
- private key;
- private key passphrase;
- terminal commands;
- terminal remote output.

## 9. SSH terminal

Terminal panel должен быть аналогичен текущему Android-приложению.

Требования:

- доступен только при активном SSH connection;
- раскрывается по спойлеру;
- ввод команд с клавиатуры;
- output отображается в terminal panel;
- команды не пишутся в diagnostics;
- output не пишется в diagnostics;
- write operations выполняются не на UI thread;
- terminal закрывается при Disconnect.

## 10. Check tunnel

Кнопка Check tunnel должна проверять доступность внешнего endpoint через SSH-туннель.

Default endpoint:

```text
youtube.com:443
```

Состояния кнопки:

- idle - серый цвет;
- checking - loading state;
- success - зелёный цвет и check icon;
- failure - красный цвет и cross icon.

## 11. Themes

Приложение должно поддерживать темы:

- System;
- Light;
- Dark;
- Custom.

Custom theme:

- RGB-настройка основных цветов;
- значения сохраняются после перезапуска;
- default custom colors соответствуют Light theme.

## 12. Storage

Обычные данные:

- SSH configs;
- SSH key metadata;
- selected config;
- app settings;
- routing mode;
- routing rules.

Секретные данные:

- SSH password;
- private key;
- private key passphrase.

Секреты должны храниться отдельно от обычных данных.

Требования:

- шифровать секреты;
- не хранить секреты в plain JSON;
- использовать Windows secure storage или собственный encrypted storage поверх системных crypto API;
- предусмотреть migration strategy при изменении формата.

## 13. UI screens

Минимальный набор экранов:

- Main screen;
- Settings;
- SSH configurations;
- Add/Edit configuration;
- SSH keys;
- Add/Edit SSH key;
- Routing rules:
  - Domains;
  - IPs;
  - Processes;
- Diagnostics panel;
- SSH terminal panel.

## 14. README и scripts

В новом проекте обязательно создать `README.md`.

README должен содержать:

- требования к окружению;
- как установить зависимости;
- как запустить приложение локально;
- как запустить dev mode;
- как собрать development EXE;
- как собрать production EXE;
- где лежат build artifacts;
- как запустить tests/lint;
- как включить diagnostics;
- какие ограничения у routing и UDP.

Нужно добавить scripts для Windows build.

Минимальный набор:

```text
scripts/check-env.ps1
scripts/install.ps1
scripts/dev.ps1
scripts/build-dev-exe.ps1
scripts/build-prod-exe.ps1
scripts/test.ps1
scripts/lint.ps1
scripts/clean.ps1
```

package scripts:

```json
{
  "scripts": {
    "dev": "electron dev command",
    "build": "production build command",
    "build:dev-exe": "development exe build command",
    "build:prod-exe": "production exe build command",
    "test": "test command",
    "lint": "lint command",
    "clean": "clean command"
  }
}
```

Development EXE должен быть удобен для локального тестирования.

Production EXE должен:

- быть оптимизирован;
- не содержать devtools по умолчанию;
- иметь production app icon;
- иметь production app name;
- иметь подпись, если signing certificate задан через env variables.

## 15. Acceptance criteria

- Приложение запускается на Windows.
- Пользователь может создать SSH-конфигурацию.
- Пользователь может добавить private key.
- Connect создаёт SSH tunnel.
- Disconnect останавливает tunnel.
- Reconnect работает после обрыва SSH.
- Routing mode `Proxy all` проксирует поддерживаемый трафик.
- Routing mode `Selected rules` проксирует только domain/IP/process.name matches.
- В `Selected rules` без enabled rules подключение запрещено.
- Check tunnel показывает success/failure.
- Diagnostics копируются в clipboard.
- Terminal принимает команды без падения UI.
- Settings сохраняются после перезапуска.
- Секреты не хранятся в plain text.
- Development EXE собирается скриптом.
- Production EXE собирается скриптом.
- README описывает локальный запуск и сборку.

## 16. Важные риски

- Низкоуровневая маршрутизация на Windows требует privileged service и аккуратной работы с Windows networking APIs.
- Полная собственная SSH-реализация сложна и должна быть выделена как отдельный этап.
- Собственный routing layer по process.name требует надёжной привязки сетевого соединения к процессу.
- Domain-based routing требует DNS visibility и корректного сопоставления domain -> IP.
- UDP support должен быть явно спроектирован отдельно; MVP может ограничиться TCP и DNS.
- Installer/service permissions и Windows security prompts нужно учитывать с самого начала.
