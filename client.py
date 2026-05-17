"""
SecureTunnel — клиент (запускается локально, на вашей машине).
Поднимает локальный SOCKS5-прокси. Браузер/приложение → SOCKS5 → шифрованный туннель → сервер → интернет.

Использование:
    python client.py --server-host <IP> --server-port 8443 --local-port 1080
"""

import asyncio
import argparse
import logging
import struct
from common import client_handshake

log = logging.getLogger("client")

# ─── SOCKS5 константы ──────────────────────────────────────────────────────────
SOCKS5_VERSION = 0x05
SOCKS5_NO_AUTH = 0x00
SOCKS5_CMD_CONNECT = 0x01
SOCKS5_ATYP_IPV4 = 0x01
SOCKS5_ATYP_DOMAIN = 0x03
SOCKS5_ATYP_IPV6 = 0x04


async def socks5_handshake(reader, writer) -> tuple[str, int]:
    """
    Разбирает SOCKS5-запрос от локального приложения.
    Возвращает (host, port) назначения.
    """
    # 1. Приветствие
    ver, nmethods = struct.unpack("BB", await reader.readexactly(2))
    await reader.readexactly(nmethods)  # методы аутентификации — игнорируем
    writer.write(bytes([SOCKS5_VERSION, SOCKS5_NO_AUTH]))
    await writer.drain()

    # 2. Запрос соединения
    ver, cmd, _, atyp = struct.unpack("BBBB", await reader.readexactly(4))
    if cmd != SOCKS5_CMD_CONNECT:
        writer.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
        await writer.drain()
        raise ValueError(f"Неподдерживаемый SOCKS5 команда: {cmd}")

    if atyp == SOCKS5_ATYP_IPV4:
        host = ".".join(map(str, await reader.readexactly(4)))
    elif atyp == SOCKS5_ATYP_DOMAIN:
        length = (await reader.readexactly(1))[0]
        host = (await reader.readexactly(length)).decode()
    elif atyp == SOCKS5_ATYP_IPV6:
        raw = await reader.readexactly(16)
        import ipaddress
        host = str(ipaddress.IPv6Address(raw))
    else:
        raise ValueError(f"Неизвестный ATYP: {atyp}")

    port = struct.unpack("!H", await reader.readexactly(2))[0]

    # 3. Ответ "успех"
    writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
    await writer.drain()

    return host, port


async def handle_local(local_reader, local_writer, server_host: str, server_port: int):
    peer = local_writer.get_extra_info("peername")
    log.info(f"Локальное подключение от {peer}")
    try:
        # 1. SOCKS5-рукопожатие — узнаём куда подключаться
        host, port = await socks5_handshake(local_reader, local_writer)
        log.info(f"SOCKS5 запрос → {host}:{port}")

        # 2. Подключаемся к нашему доверенному серверу
        s_reader, s_writer = await asyncio.open_connection(server_host, server_port)

        # 3. Шифрованное рукопожатие (X25519 ECDH)
        channel = await client_handshake(s_reader, s_writer)

        # 4. Отправляем серверу зашифрованный заголовок: куда проксировать
        host_b = host.encode()
        header = (
            port.to_bytes(2, "big") +
            len(host_b).to_bytes(1, "big") +
            host_b
        )
        await channel.send(header)
        log.info(f"Туннель установлен: localhost → [🔒 ChaCha20] → {server_host}:{server_port} → {host}:{port}")

        # 5. Двунаправленный проброс
        async def local_to_tunnel():
            try:
                while True:
                    data = await local_reader.read(65536)
                    if not data:
                        break
                    await channel.send(data)
            except Exception:
                pass
            finally:
                channel.close()

        async def tunnel_to_local():
            try:
                while True:
                    data = await channel.recv()
                    if not data:
                        break
                    local_writer.write(data)
                    await local_writer.drain()
            except Exception:
                pass
            finally:
                try:
                    local_writer.close()
                except Exception:
                    pass

        await asyncio.gather(local_to_tunnel(), tunnel_to_local())

    except Exception as e:
        log.error(f"Ошибка: {e}")
    finally:
        try:
            local_writer.close()
        except Exception:
            pass


async def main(local_host: str, local_port: int, server_host: str, server_port: int):
    handler = lambda r, w: handle_local(r, w, server_host, server_port)
    server = await asyncio.start_server(handler, local_host, local_port)
    addr = server.sockets[0].getsockname()
    log.info(
        f"SecureTunnel client запущен\n"
        f"  SOCKS5 прокси : {addr[0]}:{addr[1]}\n"
        f"  Сервер        : {server_host}:{server_port}\n"
        f"  Шифрование    : X25519 ECDH + ChaCha20-Poly1305"
    )
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SecureTunnel Client")
    parser.add_argument("--local-host", default="127.0.0.1")
    parser.add_argument("--local-port", type=int, default=1080)
    parser.add_argument("--server-host", required=True, help="IP вашего доверенного сервера")
    parser.add_argument("--server-port", type=int, default=8443)
    args = parser.parse_args()
    asyncio.run(main(args.local_host, args.local_port, args.server_host, args.server_port))
