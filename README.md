# SecureTunnel 🔐

Кроссплатформенный инструмент для **end-to-end шифрования трафика поверх VPN**.  
Даже если VPN-провайдер пишет ваши данные — он увидит только зашифрованный поток.

```
Браузер/приложение
       │  SOCKS5 (локально)
       ▼
  client.py  ──[X25519 ECDH + ChaCha20-Poly1305]──▶  server.py  ──▶  Интернет
  (ваш ПК)              (зашифрованный туннель)        (ваш VPS)
```

## Архитектура безопасности

| Компонент | Алгоритм | Назначение |
|-----------|----------|------------|
| Обмен ключами | X25519 ECDH | Forward Secrecy — каждая сессия новый ключ |
| Симметричное шифрование | ChaCha20-Poly1305 (AEAD) | Шифрование + аутентификация данных |
| KDF | HKDF-SHA256 | Вывод ключа из DH-секрета |
| Фрейминг | 4-байт length prefix | Разбивка потока на блоки |

**Forward Secrecy**: при каждом подключении генерируются новые X25519-ключи.  
Компрометация долгосрочного секрета не раскрывает прошлые сессии.

**Аутентификация**: Poly1305-тег на каждом фрейме — любое изменение данных  
в транзите немедленно обнаруживается (`InvalidTag`).

---

## Быстрый старт

### Зависимости

```bash
pip3 install -r requirements.txt
```

### 1. На вашем доверенном сервере (VPS вне VPN)

```bash
python3 server.py --host 0.0.0.0 --port 8443
```

### 2. На вашей машине (клиент)

```bash
python3 client.py --server-host 1.2.3.4 --server-port 8443 --local-port 1080
```

### 3. Настройте приложения на использование SOCKS5

- **Браузер**: Настройки → Прокси → SOCKS5 → `127.0.0.1:1080`  
- **curl**: `curl --socks5 127.0.0.1:1080 https://example.com`  
- **wget**: `wget -e "https_proxy=socks5://127.0.0.1:1080" https://example.com`  
- **git**: `git config --global http.proxy socks5://127.0.0.1:1080`  
- **Системный прокси (Linux)**: `export ALL_PROXY=socks5://127.0.0.1:1080`

---

## Docker

### Сервер

```bash
docker build -f Dockerfile.server -t securetunnel-server .
docker run -d -p 8443:8443 --name st-server securetunnel-server
```

### Клиент

```bash
docker build -f Dockerfile.client -t securetunnel-client .
docker run -d -p 1080:1080 --name st-client \
  -e SERVER_HOST=1.2.3.4 -e SERVER_PORT=8443 \
  securetunnel-client
```

### Docker Compose (всё сразу, для локального теста)

```bash
docker compose up
```

---

## Systemd (автозапуск)

### Сервер (на VPS)

```bash
sudo cp securetunnel-server.service /etc/systemd/system/
sudo systemctl enable --now securetunnel-server
sudo systemctl status securetunnel-server
```

### Клиент (на вашей машине)

```bash
# Отредактируйте SERVER_HOST в файле перед установкой
sudo cp securetunnel-client.service /etc/systemd/system/
sudo systemctl enable --now securetunnel-client
sudo systemctl status securetunnel-client
```

---

## Тесты

```bash
pytest test_tunnel.py -v
```

```
test_keypair_generation       PASSED  — генерация X25519 ключей
test_ecdh_symmetry            PASSED  — обе стороны получают одинаковый ключ
test_ecdh_unique_per_session  PASSED  — каждая сессия уникальна
test_secure_channel_roundtrip PASSED  — данные шифруются и расшифровываются
test_large_payload            PASSED  — корректная фрагментация (200 KB)
test_tamper_detection         PASSED  — подмена данных обнаруживается
```

---

## Структура проекта

```
securetunnel/
├── common.py                   # Crypto-ядро: ECDH, SecureChannel
├── client.py                   # SOCKS5-прокси + шифрованный клиент
├── server.py                   # Шифрованный сервер + TCP-прокси
├── test_tunnel.py              # Тесты (pytest-asyncio)
├── requirements.txt
├── Dockerfile.server
├── Dockerfile.client
├── docker-compose.yml
├── securetunnel-server.service # systemd
└── securetunnel-client.service # systemd
```

---

## Ограничения и TODO

- [ ] Аутентификация клиента (pre-shared key или сертификаты) — сейчас любой может подключиться к серверу
- [ ] UDP-проксирование (сейчас только TCP)
- [ ] Obfuscation (трафик может быть обнаружен как кастомный протокол — можно добавить TLS-обёртку)
- [ ] Ротация ключей внутри сессии
