"""
SecureTunnel — общие утилиты: шифрование, протокол, логирование.
Шифрование: X25519 ECDH (обмен ключами) + ChaCha20-Poly1305 (AEAD).
"""

import os
import struct
import logging
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)

# Заголовок фрейма: 4 байта длина зашифрованного блока
FRAME_HEADER = ">I"
FRAME_HEADER_SIZE = 4
MAX_FRAME = 65535  # байт payload за раз


def generate_keypair():
    """Генерирует пару ключей X25519."""
    private = X25519PrivateKey.generate()
    public = private.public_key()
    return private, public


def public_key_bytes(pub_key) -> bytes:
    return pub_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )


def derive_shared_key(private_key, peer_public_bytes: bytes) -> bytes:
    """ECDH + HKDF → 32-байтный симметричный ключ."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    peer_pub = X25519PublicKey.from_public_bytes(peer_public_bytes)
    shared = private_key.exchange(peer_pub)
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"securetunnel-v1",
    ).derive(shared)
    return derived


class SecureChannel:
    """
    Обёртка над asyncio reader/writer с прозрачным шифрованием.
    Каждый фрейм: [4 байта длина][nonce(12)][ciphertext+tag(16)]
    """

    def __init__(self, reader, writer, key: bytes):
        self.reader = reader
        self.writer = writer
        self._cipher = ChaCha20Poly1305(key)
        self.log = logging.getLogger("SecureChannel")

    def _encrypt(self, data: bytes) -> bytes:
        nonce = os.urandom(12)
        ct = self._cipher.encrypt(nonce, data, None)
        return nonce + ct

    def _decrypt(self, frame: bytes) -> bytes:
        nonce, ct = frame[:12], frame[12:]
        return self._cipher.decrypt(nonce, ct, None)

    async def send(self, data: bytes):
        """Шифрует и отправляет данные фреймами."""
        for i in range(0, max(len(data), 1), MAX_FRAME):
            chunk = data[i:i + MAX_FRAME]
            encrypted = self._encrypt(chunk)
            header = struct.pack(FRAME_HEADER, len(encrypted))
            self.writer.write(header + encrypted)
        await self.writer.drain()

    async def recv(self) -> bytes:
        """Читает один фрейм и расшифровывает."""
        header = await self.reader.readexactly(FRAME_HEADER_SIZE)
        length = struct.unpack(FRAME_HEADER, header)[0]
        frame = await self.reader.readexactly(length)
        return self._decrypt(frame)

    def close(self):
        try:
            self.writer.close()
        except Exception:
            pass


async def server_handshake(reader, writer) -> SecureChannel:
    """
    Сторона сервера: получает публичный ключ клиента, отправляет свой.
    Возвращает SecureChannel с общим ключом.
    """
    private, public = generate_keypair()
    # 1. Читаем публичный ключ клиента (32 байта)
    client_pub_bytes = await reader.readexactly(32)
    # 2. Отправляем свой публичный ключ
    writer.write(public_key_bytes(public))
    await writer.drain()
    # 3. Вычисляем общий ключ
    key = derive_shared_key(private, client_pub_bytes)
    return SecureChannel(reader, writer, key)


async def client_handshake(reader, writer) -> SecureChannel:
    """
    Сторона клиента: отправляет публичный ключ, получает серверный.
    Возвращает SecureChannel с общим ключом.
    """
    private, public = generate_keypair()
    # 1. Отправляем свой публичный ключ
    writer.write(public_key_bytes(public))
    await writer.drain()
    # 2. Читаем публичный ключ сервера
    server_pub_bytes = await reader.readexactly(32)
    # 3. Вычисляем общий ключ
    key = derive_shared_key(private, server_pub_bytes)
    return SecureChannel(reader, writer, key)
