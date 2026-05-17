"""
SecureTunnel — сервер (запускается на доверенной машине, вне VPN).
Принимает зашифрованные соединения от клиента и проксирует их в интернет.

Использование:
    python server.py --host 0.0.0.0 --port 8443
"""

import asyncio
import argparse
import logging
from common import server_handshake

log = logging.getLogger("server")


async def forward(src_read, dst_write, label: str):
    """Перекачивает байты из src в dst до EOF."""
    try:
        while True:
            data = await src_read(65536)
            if not data:
                break
            dst_write(data)
    except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
        pass
    except Exception as e:
        log.debug(f"{label}: {e}")


async def handle_socks5_target(channel, target_host: str, target_port: int):
    """Открывает TCP-соединение к целевому хосту и проксирует трафик."""
    try:
        t_reader, t_writer = await asyncio.open_connection(target_host, target_port)
    except Exception as e:
        log.warning(f"Не удалось подключиться к {target_host}:{target_port} — {e}")
        await channel.send(b"\x00\x5a\x00\x00\x00\x00\x00\x00")  # SOCKS4 reject
        channel.close()
        return

    log.info(f"Туннель → {target_host}:{target_port}")

    async def tunnel_in():
        """Клиент → целевой хост (расшифровываем)."""
        try:
            while True:
                data = await channel.recv()
                if not data:
                    break
                t_writer.write(data)
                await t_writer.drain()
        except Exception:
            pass
        finally:
            try:
                t_writer.close()
            except Exception:
                pass

    async def tunnel_out():
        """Целевой хост → клиент (шифруем)."""
        try:
            while True:
                data = await t_reader.read(65536)
                if not data:
                    break
                await channel.send(data)
        except Exception:
            pass
        finally:
            channel.close()

    await asyncio.gather(tunnel_in(), tunnel_out())


async def handle_client(reader, writer):
    peer = writer.get_extra_info("peername")
    log.info(f"Новое подключение от {peer}")
    try:
        # Рукопожатие — обмен ключами
        channel = await server_handshake(reader, writer)

        # Читаем первый зашифрованный пакет — заголовок запроса
        # Формат: [2 байта port][hostname длина 1 байт][hostname bytes]
        header = await channel.recv()
        port = int.from_bytes(header[:2], "big")
        host_len = header[2]
        host = header[3: 3 + host_len].decode()

        await handle_socks5_target(channel, host, port)
    except Exception as e:
        log.error(f"Ошибка обработки {peer}: {e}")
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def main(host: str, port: int):
    server = await asyncio.start_server(handle_client, host, port)
    addr = server.sockets[0].getsockname()
    log.info(f"SecureTunnel server слушает {addr[0]}:{addr[1]}")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SecureTunnel Server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8443)
    args = parser.parse_args()
    asyncio.run(main(args.host, args.port))
