from itertools import product
import pytest
from typing import List, Any, Tuple
from hashlib import sha256
import os


class FeistelBlockCipher:
    @staticmethod
    def __equalize_length(a: List[Any], b: List[Any]
                          ) -> Tuple[List[Any], List[Any]]:
        if len(a) == 0:
            return b, b
        if len(b) == 0:
            return a, a
        if len(a) == len(b):
            return a, b
        if len(a) < len(b):
            b, a = FeistelBlockCipher.__equalize_length(b, a)
            return a, b
        return a, (b * (len(a) // len(b) + 1))[:len(a)]

    @staticmethod
    def xor_bytes(a: List[int], b: List[int]) -> List[int]:
        a, b = FeistelBlockCipher.__equalize_length(a, b)
        return bytes(x ^ y for x, y in zip(a, b))

    @staticmethod
    def __feistal_encrypt_block(block: List[int],
                                key: List[int],
                                rounds: int = 10) -> List[int]:
        if len(block) > 16:
            raise ValueError(
                "block must be 16 bytes long, got %d" % len(block))
        if len(block) < 16:
            block += b"\x00" * (16 - len(block))
        L, R = block[:8], block[8:]
        for _ in range(rounds):
            F = sha256(key + R).digest()[:8]
            L, R = R, FeistelBlockCipher.xor_bytes(L, F)
        return L + R

    @staticmethod
    def __feistal_decrypt_block(block: List[int],
                                key: List[int],
                                rounds: int = 10) -> List[int]:
        if len(block) != 16:
            raise ValueError(
                "block must be 16 bytes long, got %d" % len(block))
        L, R = block[:8], block[8:]
        for _ in range(rounds):
            F = sha256(key + L).digest()[:8]
            R, L = L, FeistelBlockCipher.xor_bytes(R, F)
        return (L + R).rstrip(b"\x00")

    @staticmethod
    def feistel_encrypt(plaintext: List[int],
                        key: List[int],
                        rounds: int = 10) -> List[int]:
        blocks = [plaintext[i:i + 16] for i in range(0, len(plaintext), 16)]
        encrypted = b""
        for block in blocks:
            encrypted += FeistelBlockCipher.__feistal_encrypt_block(
                block, key, rounds)
        return encrypted

    @staticmethod
    def feistel_decrypt(ciphertext: List[int],
                        key: List[int],
                        rounds: int = 10) -> List[int]:
        blocks = [ciphertext[i:i + 16] for i in range(0, len(ciphertext), 16)]
        decrypted = b""
        for block in blocks:
            decrypted += FeistelBlockCipher.__feistal_decrypt_block(
                block, key, rounds)
        return decrypted

    @staticmethod
    def cbc_encrypt(plaintext: List[int],
                    key: List[int],
                    iv: List[int]) -> List[int]:
        blocks = [plaintext[i:i + 16] for i in range(0, len(plaintext), 16)]
        ciphertext = b""
        prev = iv
        for block in blocks:
            if len(block) < 16:
                block += b"\x00" * (16 - len(block))
            x = FeistelBlockCipher.xor_bytes(block, prev)
            c = FeistelBlockCipher.__feistal_encrypt_block(x, key, 4)
            ciphertext += c
            prev = c
        return ciphertext

    @staticmethod
    def cbc_decrypt(ciphertext: List[int],
                    key: List[int],
                    iv: List[int]) -> List[int]:
        blocks = [ciphertext[i:i + 16] for i in range(0, len(ciphertext), 16)]
        plaintext = b""
        prev = iv
        for c in blocks:
            x = FeistelBlockCipher.__feistal_decrypt_block(c, key, 4)
            p = FeistelBlockCipher.xor_bytes(x, prev)
            plaintext += p.rstrip(b"\x00")
            prev = c
        return plaintext

    @staticmethod
    def ofb_encrypt(plaintext: List[int],
                    key: List[int],
                    iv: List[int]) -> List[int]:
        blocks = [plaintext[i:i + 16] for i in range(0, len(plaintext), 16)]
        ciphertext = b""
        state = iv
        for block in blocks:
            if len(block) < 16:
                block += b"\x00" * (16 - len(block))
            state = FeistelBlockCipher.__feistal_encrypt_block(state, key, 4)
            c = FeistelBlockCipher.xor_bytes(block, state)
            ciphertext += c.rstrip(b"\x00")
        return ciphertext

    @staticmethod
    def ofb_decrypt(ciphertext: List[int],
                    key: List[int],
                    iv: List[int]) -> List[int]:
        return FeistelBlockCipher.ofb_encrypt(ciphertext, key, iv)

    @staticmethod
    def test_encryptors():
        key = b"key"
        plaintext = b"This is a test message for encryption."
        iv = os.urandom(16)

        encrypted = FeistelBlockCipher.feistel_encrypt(plaintext, key)
        decrypted = FeistelBlockCipher.feistel_decrypt(encrypted, key)
        print("Algorithm: Feistel")
        print(f"Original: {plaintext}")
        print(f"Encrypted: {encrypted.hex()}")
        print(f"Decrypted: {decrypted}")
        print(f"Decryption Success: {decrypted == plaintext}\n")

        encrypted = FeistelBlockCipher.xor_bytes(plaintext, key)
        decrypted = FeistelBlockCipher.xor_bytes(encrypted, key)
        print("Algorithm: XOR")
        print(f"Original: {plaintext}")
        print(f"Encrypted: {encrypted.hex()}")
        print(f"Decrypted: {decrypted}")
        print(f"Decryption Success: {decrypted == plaintext}\n")

        encrypted = FeistelBlockCipher.cbc_encrypt(plaintext, key, iv)
        decrypted = FeistelBlockCipher.cbc_decrypt(encrypted, key, iv)
        print("Algorithm: CBC")
        print(f"Original: {plaintext}")
        print(f"Encrypted: {encrypted.hex()}")
        print(f"Decrypted: {decrypted}")
        print(f"Decryption Success: {decrypted == plaintext}\n")

        encrypted = FeistelBlockCipher.ofb_encrypt(plaintext, key, iv)
        decrypted = FeistelBlockCipher.ofb_decrypt(encrypted, key, iv)
        print("Algorithm: OFB")
        print(f"Original: {plaintext}")
        print(f"Encrypted: {encrypted.hex()}")
        print(f"Decrypted: {decrypted}")
        print(f"Decryption Success: {decrypted == plaintext}\n")


class Metadata:
    marker = b"EmirhanAltunel"
    # Metadata format: [metadata]||[file_hash]][metadata_length][marker][iv]

    @staticmethod
    def add_metadata(filename: str, key: List[int], metadata_str: str) -> None:
        meta_exists = False
        with open(filename, "rb") as f:
            data = f.read()
            marker = data[-16 - len(Metadata.marker):-16]
            if marker == Metadata.marker:
                meta_exists = True
                meta_len = int.from_bytes(data[-16 - len(Metadata.marker) - 8:
                                               -16 - len(Metadata.marker)],
                                          'big')
                data = data[:-16 - len(Metadata.marker) - meta_len - 8]
        file_hash = sha256(data).hexdigest()
        metadata = metadata_str.encode(
            "utf-8") + b"||" + file_hash.encode("utf-8")
        iv = os.urandom(16)
        encrypted_metadata = FeistelBlockCipher.cbc_encrypt(
            metadata, key, iv)
        metadata_len = len(encrypted_metadata).to_bytes(8, 'big')
        with open(filename, "r+b") as f:
            if meta_exists:
                f.seek(-16 - len(Metadata.marker) - meta_len - 8, 2)
            else:
                f.seek(0, 2)
            f.write(encrypted_metadata + metadata_len + Metadata.marker + iv)

    @staticmethod
    def extract_metadata(filename: str, key: List[int]) -> Tuple[str, str]:
        with open(filename, "rb") as f:
            f.seek(-16 - len(Metadata.marker) - 8, 2)
            meta_len = int.from_bytes(f.read(8), 'big')
            marker = f.read(len(Metadata.marker))
            if marker != Metadata.marker:
                return None, None
            iv = f.read(16)
            f.seek(-16 - len(Metadata.marker) - 8 - meta_len, 2)
            metadata = f.read(meta_len)
        metadata = FeistelBlockCipher.cbc_decrypt(metadata, key, iv)
        metadata, file_hash = metadata.split(b"||")
        return metadata.decode("utf-8"), file_hash.decode("utf-8")

    @staticmethod
    def verify_metadata(filename: str, key: List[int]) -> bool:
        metadata, file_hash = Metadata.extract_metadata(filename, key)
        if metadata is None:
            return False
        with open(filename, "rb") as f:
            data = f.read()
            f.seek(-16 - len(Metadata.marker) - 8, 2)
            meta_len = int.from_bytes(f.read(8), 'big')
            data = data[:-16 - len(Metadata.marker) - meta_len - 8]
        new_hash = sha256(data).hexdigest()
        return new_hash == file_hash

    @staticmethod
    def test_metadata():
        filename = "test.pdf"
        key = b"Emirhan Altunel"
        metadata = "This is a metadata. Created by Emirhan Altunel."
        Metadata.add_metadata(filename, key, metadata)
        extracted_metadata, original_hash = Metadata.extract_metadata(
            filename, key)
        print("Metadata Test")
        print(f"Metadata: {metadata}")
        print("Applying metadata")
        print(f"Extracted Metadata: {extracted_metadata}")
        print(f"Original Hash: {original_hash}")
        print(f"Verification: {Metadata.verify_metadata(filename, key)}")
        print("Modifying file...")
        with open(filename, "a") as f:
            f.write("This is a modification.")
        print(f"Verification: {Metadata.verify_metadata(filename, key)}")


if __name__ == "__main__":
    FeistelBlockCipher.test_encryptors()
    Metadata.test_metadata()
