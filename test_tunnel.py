"""
SecureTunnel — тесты (pytest + pytest-asyncio).
Запуск: pytest test_tunnel.py -v
"""

import asyncio
import pytest
import pytest_asyncio
from common import (
    generate_keypair, public_key_bytes, derive_shared_key,
    SecureChannel, server_handshake, client_handshake
)


# ─── Тесты крипто-примитивов ───────────────────────────────────────────────────

def test_keypair_generation():
    priv, pub = generate_keypair()
    pub_b = public_key_bytes(pub)
    assert len(pub_b) == 32


def test_ecdh_symmetry():
    """Оба участника должны получить одинаковый общий ключ."""
    priv_a, pub_a = generate_keypair()
    priv_b, pub_b = generate_keypair()
    key_a = derive_shared_key(priv_a, public_key_bytes(pub_b))
    key_b = derive_shared_key(priv_b, public_key_bytes(pub_a))
    assert key_a == key_b
    assert len(key_a) == 32


def test_ecdh_unique_per_session():
    """Каждая сессия должна давать уникальный ключ."""
    priv_a, pub_a = generate_keypair()
    priv_b, pub_b = generate_keypair()
    key1 = derive_shared_key(priv_a, public_key_bytes(pub_b))

    priv_c, pub_c = generate_keypair()
    key2 = derive_shared_key(priv_a, public_key_bytes(pub_c))
    assert key1 != key2


# ─── Тесты SecureChannel через in-memory pipes ─────────────────────────────────

class MemoryStream:
    """Байтовый буфер, имитирующий StreamReader/StreamWriter."""
    def __init__(self):
        self._buf = bytearray()
        self._event = asyncio.Event()

    async def readexactly(self, n: int) -> bytes:
        while len(self._buf) < n:
            self._event.clear()
            await self._event.wait()
        data = bytes(self._buf[:n])
        del self._buf[:n]
        return data

    async def read(self, n: int) -> bytes:
        return await self.readexactly(n)

    def write(self, data: bytes):
        self._buf.extend(data)
        self._event.set()

    async def drain(self):
        pass

    def close(self):
        pass


def make_pipe():
    """Создаёт две связанные пары (reader, writer)."""
    ab = MemoryStream()  # данные от A к B
    ba = MemoryStream()  # данные от B к A

    class ReaderA:
        readexactly = ba.readexactly
        read = ba.read

    class WriterA:
        write = ab.write
        drain = ab.drain
        close = ab.close
        get_extra_info = lambda self, x: ("127.0.0.1", 9999)

    class ReaderB:
        readexactly = ab.readexactly
        read = ab.read

    class WriterB:
        write = ba.write
        drain = ba.drain
        close = ba.close
        get_extra_info = lambda self, x: ("127.0.0.1", 9998)

    return (ReaderA(), WriterA()), (ReaderB(), WriterB())


@pytest.mark.asyncio
async def test_secure_channel_roundtrip():
    """Данные должны дойти зашифрованными и расшифроваться обратно."""
    (ra, wa), (rb, wb) = make_pipe()

    async def run_server():
        return await server_handshake(rb, wb)

    async def run_client():
        return await client_handshake(ra, wa)

    ch_server, ch_client = await asyncio.gather(run_server(), run_client())

    # Клиент → Сервер
    await ch_client.send(b"Hello, SecureTunnel!")
    received = await ch_server.recv()
    assert received == b"Hello, SecureTunnel!"

    # Сервер → Клиент
    await ch_server.send(b"OK, encrypted!")
    received = await ch_client.recv()
    assert received == b"OK, encrypted!"


@pytest.mark.asyncio
async def test_large_payload():
    """Большой payload должен корректно разбиваться на фреймы."""
    (ra, wa), (rb, wb) = make_pipe()

    async def run_server():
        return await server_handshake(rb, wb)

    async def run_client():
        return await client_handshake(ra, wa)

    ch_server, ch_client = await asyncio.gather(run_server(), run_client())

    big_data = b"X" * 200_000
    await ch_client.send(big_data)

    # Собираем все фреймы
    received = bytearray()
    while len(received) < len(big_data):
        chunk = await ch_server.recv()
        received.extend(chunk)

    assert bytes(received) == big_data


@pytest.mark.asyncio
async def test_tamper_detection():
    """Изменение зашифрованного фрейма должно вызывать исключение."""
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    import os
    key = os.urandom(32)
    cipher = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    ct = cipher.encrypt(nonce, b"secret", None)

    # Портим один байт в ciphertext
    tampered = bytearray(ct)
    tampered[5] ^= 0xFF

    from cryptography.exceptions import InvalidTag
    with pytest.raises(InvalidTag):
        cipher.decrypt(nonce, bytes(tampered), None)
