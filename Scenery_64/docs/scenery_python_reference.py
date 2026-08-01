"""Reference implementation of the SCENERY-64/80 block cipher.

The implementation follows the specification in:
    Jingya Feng and Lang Li,
    "SCENERY: a lightweight block cipher based on Feistel structure",
    Frontiers of Computer Science, 16(3), 163813, 2022.

This module prioritizes readability, auditability, and exact reproduction of the
four test vectors in the paper. It is not intended as a hardened production
cryptographic implementation.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Iterable, Sequence

BLOCK_SIZE_BYTES = 8
KEY_SIZE_BYTES = 10
NUM_ROUNDS = 28
MASK8 = 0xFF
MASK32 = 0xFFFFFFFF
MASK64 = 0xFFFFFFFFFFFFFFFF
MASK80 = (1 << 80) - 1

# Table 3 of the paper; identical to the RECTANGLE S-box.
SBOX: tuple[int, ...] = (
    0x6, 0x5, 0xC, 0xA,
    0x1, 0xE, 0x7, 0x9,
    0xB, 0x0, 0x3, 0xD,
    0x8, 0xF, 0x4, 0x2,
)


class SceneryError(ValueError):
    """Raised when an input violates the SCENERY block/key specification."""


def _rotl8(value: int, amount: int) -> int:
    """Rotate an 8-bit value left by ``amount`` positions."""
    amount %= 8
    value &= MASK8
    return ((value << amount) | (value >> ((8 - amount) % 8))) & MASK8


def _rotr8(value: int, amount: int) -> int:
    """Rotate an 8-bit value right by ``amount`` positions."""
    return _rotl8(value, -amount)


def _rotl80(value: int, amount: int) -> int:
    """Rotate an 80-bit value left by ``amount`` positions."""
    amount %= 80
    value &= MASK80
    return ((value << amount) | (value >> ((80 - amount) % 80))) & MASK80


def _replace_msb_bit_slice(value: int, start: int, width: int, replacement: int) -> int:
    """Replace a bit slice addressed from the most-significant end.

    Bit 0 is the most-significant bit of the 80-bit key, matching the paper's
    notation k_0, ..., k_79.
    """
    if not (0 <= start <= 80 - width):
        raise SceneryError("invalid MSB-oriented bit slice")
    if not (0 <= replacement < (1 << width)):
        raise SceneryError("replacement does not fit in the requested width")

    shift = 80 - (start + width)
    mask = ((1 << width) - 1) << shift
    return (value & ~mask) | (replacement << shift)


def sub_columns(word: int) -> int:
    """Apply the eight parallel 4x4 S-boxes of SCENERY.

    The 32-bit input is represented as four bytes L0 || L1 || L2 || L3.
    For each bit position j, the S-box input is

        L0[j] + 2*L1[j] + 4*L2[j] + 8*L3[j].

    Thus L0 is the least-significant coordinate of each bitsliced nibble.
    This ordering is the one that reproduces the appendix test vectors.
    """
    if not (0 <= word <= MASK32):
        raise SceneryError("SubColumns input must be a 32-bit integer")

    rows = list(word.to_bytes(4, byteorder="big"))
    output_rows = [0, 0, 0, 0]

    for bit_index in range(8):
        nibble = (
            ((rows[0] >> bit_index) & 1)
            | (((rows[1] >> bit_index) & 1) << 1)
            | (((rows[2] >> bit_index) & 1) << 2)
            | (((rows[3] >> bit_index) & 1) << 3)
        )
        substituted = SBOX[nibble]

        for row_index in range(4):
            output_rows[row_index] |= (
                ((substituted >> row_index) & 1) << bit_index
            )

    return int.from_bytes(bytes(output_rows), byteorder="big")


def mix_columns(word: int) -> int:
    """Apply the 32x32 binary linear layer from Section 3.2.

    For input bytes L0, L1, L2, L3:

        t   = ROL8(L1, 1) XOR ROR8(L0, 3)
        L0' = ROR8(L0, 2) XOR t
        L1' = L1 XOR t

        z   = ROL8(L3, 4) XOR ROL8(L2, 1)
        L2' = L2 XOR z
        L3' = ROR8(L3, 3) XOR z
    """
    if not (0 <= word <= MASK32):
        raise SceneryError("MixColumns input must be a 32-bit integer")

    l0, l1, l2, l3 = word.to_bytes(4, byteorder="big")

    t = _rotl8(l1, 1) ^ _rotr8(l0, 3)
    out0 = _rotr8(l0, 2) ^ t
    out1 = l1 ^ t

    z = _rotl8(l3, 4) ^ _rotl8(l2, 1)
    out2 = l2 ^ z
    out3 = _rotr8(l3, 3) ^ z

    return int.from_bytes(bytes((out0, out1, out2, out3)), byteorder="big")


def round_function(left: int, round_key: int) -> tuple[int, int, int]:
    """Evaluate AddRoundKey, SubColumns, and MixColumns.

    Returns a tuple ``(after_add_key, after_subcolumns, after_mixcolumns)``
    so callers can inspect every component of the round function.
    """
    if not (0 <= left <= MASK32):
        raise SceneryError("left half must be a 32-bit integer")
    if not (0 <= round_key <= MASK32):
        raise SceneryError("round key must be a 32-bit integer")

    after_add_key = left ^ round_key
    after_subcolumns = sub_columns(after_add_key)
    after_mixcolumns = mix_columns(after_subcolumns)
    return after_add_key, after_subcolumns, after_mixcolumns


def update_key_state(key_state: int, round_number: int) -> int:
    """Compute the next 80-bit key state.

    The four steps are exactly those specified in Section 2.4:

    1. Apply S to k_12..k_15 and k_28..k_31.
    2. Rotate the 80-bit state left by 11 bits.
    3. XOR the 5-bit round number into post-rotation bits k_11..k_15.
    4. Let v0 be the *input-state* bits k_14||k_15 and rotate the ten
       bytes of the intermediate state left by 2*v0 byte positions.
    """
    if not (0 <= key_state <= MASK80):
        raise SceneryError("key state must be an 80-bit integer")
    if not (1 <= round_number <= 31):
        raise SceneryError("round number must fit in the specified 5-bit constant")

    input_state = key_state

    # Step 1: SubCells at the two MSB-oriented nibble positions.
    nibble_12 = (key_state >> 64) & 0xF
    nibble_28 = (key_state >> 48) & 0xF
    key_state = _replace_msb_bit_slice(key_state, 12, 4, SBOX[nibble_12])
    key_state = _replace_msb_bit_slice(key_state, 28, 4, SBOX[nibble_28])

    # Step 2: 80-bit left cyclic shift.
    key_state = _rotl80(key_state, 11)

    # Step 3: XOR i_4..i_0 into post-rotation k_11..k_15.
    key_state ^= (round_number & 0x1F) << 64

    # Step 4: Dynamic Permutation. v0 is read from the input K^i.
    v0 = (input_state >> 64) & 0x3  # input bits k_14||k_15
    bytes_state = list(key_state.to_bytes(KEY_SIZE_BYTES, byteorder="big"))
    byte_shift = (2 * v0) % 10
    bytes_state = bytes_state[byte_shift:] + bytes_state[:byte_shift]

    return int.from_bytes(bytes(bytes_state), byteorder="big")


def generate_round_keys(master_key: bytes, rounds: int = NUM_ROUNDS) -> tuple[int, ...]:
    """Generate ``rounds`` 32-bit subkeys from a 10-byte master key.

    Round 1 uses the first four bytes of the original master key. The key
    state is updated with round constant i after subkey i has been emitted.
    """
    if not isinstance(master_key, (bytes, bytearray, memoryview)):
        raise TypeError("master_key must be a bytes-like object")
    master_key = bytes(master_key)
    if len(master_key) != KEY_SIZE_BYTES:
        raise SceneryError(
            f"SCENERY requires a {KEY_SIZE_BYTES}-byte (80-bit) key"
        )
    if not (1 <= rounds <= NUM_ROUNDS):
        raise SceneryError(f"rounds must be in the range 1..{NUM_ROUNDS}")

    key_state = int.from_bytes(master_key, byteorder="big")
    round_keys: list[int] = []

    for round_number in range(1, rounds + 1):
        round_keys.append((key_state >> 48) & MASK32)
        key_state = update_key_state(key_state, round_number)

    return tuple(round_keys)


@dataclass(frozen=True, slots=True)
class RoundTrace:
    """Complete observable state of one encryption/decryption round."""

    round_number: int
    round_key: int
    left_in: int
    right_in: int
    after_add_key: int
    after_subcolumns: int
    after_mixcolumns: int
    left_out: int
    right_out: int

    def as_hex_dict(self) -> dict[str, int | str]:
        """Return a JSON-friendly representation with fixed-width hex fields."""
        raw = asdict(self)
        return {
            "round_number": self.round_number,
            "round_key": f"{self.round_key:08X}",
            "left_in": f"{self.left_in:08X}",
            "right_in": f"{self.right_in:08X}",
            "after_add_key": f"{self.after_add_key:08X}",
            "after_subcolumns": f"{self.after_subcolumns:08X}",
            "after_mixcolumns": f"{self.after_mixcolumns:08X}",
            "left_out": f"{self.left_out:08X}",
            "right_out": f"{self.right_out:08X}",
        }


class SCENERY:
    """Reusable SCENERY-64/80 cipher object."""

    block_size = BLOCK_SIZE_BYTES
    key_size = KEY_SIZE_BYTES
    rounds = NUM_ROUNDS

    def __init__(self, key: bytes):
        if not isinstance(key, (bytes, bytearray, memoryview)):
            raise TypeError("key must be a bytes-like object")
        self._key = bytes(key)
        if len(self._key) != KEY_SIZE_BYTES:
            raise SceneryError(
                f"SCENERY requires a {KEY_SIZE_BYTES}-byte (80-bit) key"
            )
        self._round_keys = generate_round_keys(self._key)

    @property
    def key(self) -> bytes:
        """Return the immutable 80-bit master key."""
        return self._key

    @property
    def round_keys(self) -> tuple[int, ...]:
        """Return all 28 round keys as 32-bit integers."""
        return self._round_keys

    @staticmethod
    def _validate_block(block: bytes) -> bytes:
        if not isinstance(block, (bytes, bytearray, memoryview)):
            raise TypeError("block must be a bytes-like object")
        block = bytes(block)
        if len(block) != BLOCK_SIZE_BYTES:
            raise SceneryError(
                f"SCENERY operates on exactly {BLOCK_SIZE_BYTES} bytes"
            )
        return block

    @staticmethod
    def _crypt(
        block: bytes,
        round_keys: Sequence[int],
        *,
        with_trace: bool,
    ) -> tuple[bytes, tuple[RoundTrace, ...]]:
        block = SCENERY._validate_block(block)
        state = int.from_bytes(block, byteorder="big")
        left = (state >> 32) & MASK32
        right = state & MASK32
        trace: list[RoundTrace] = []

        for round_number, round_key in enumerate(round_keys, start=1):
            left_in, right_in = left, right
            add_key, sub, mixed = round_function(left_in, round_key)

            # Balanced Feistel round:
            #   R_{i+1} = L_i
            #   L_{i+1} = R_i XOR F(L_i, SK_i)
            left = right_in ^ mixed
            right = left_in

            if with_trace:
                trace.append(
                    RoundTrace(
                        round_number=round_number,
                        round_key=round_key,
                        left_in=left_in,
                        right_in=right_in,
                        after_add_key=add_key,
                        after_subcolumns=sub,
                        after_mixcolumns=mixed,
                        left_out=left,
                        right_out=right,
                    )
                )

        # Algorithm 1 outputs R_{Nr+1} || L_{Nr+1}.
        output = ((right & MASK32) << 32) | (left & MASK32)
        return output.to_bytes(BLOCK_SIZE_BYTES, byteorder="big"), tuple(trace)

    def encrypt_block(self, plaintext: bytes) -> bytes:
        """Encrypt one 64-bit block."""
        ciphertext, _ = self._crypt(
            plaintext, self._round_keys, with_trace=False
        )
        return ciphertext

    def decrypt_block(self, ciphertext: bytes) -> bytes:
        """Decrypt one 64-bit block using the reversed subkey order."""
        plaintext, _ = self._crypt(
            ciphertext, tuple(reversed(self._round_keys)), with_trace=False
        )
        return plaintext

    def encrypt_block_with_trace(
        self, plaintext: bytes
    ) -> tuple[bytes, tuple[RoundTrace, ...]]:
        """Encrypt one block and return all 28 internal round records."""
        return self._crypt(plaintext, self._round_keys, with_trace=True)

    def decrypt_block_with_trace(
        self, ciphertext: bytes
    ) -> tuple[bytes, tuple[RoundTrace, ...]]:
        """Decrypt one block and return all 28 internal round records."""
        return self._crypt(
            ciphertext, tuple(reversed(self._round_keys)), with_trace=True
        )


def encrypt_block(plaintext: bytes, key: bytes) -> bytes:
    """One-shot helper for encrypting a single block."""
    return SCENERY(key).encrypt_block(plaintext)


def decrypt_block(ciphertext: bytes, key: bytes) -> bytes:
    """One-shot helper for decrypting a single block."""
    return SCENERY(key).decrypt_block(ciphertext)


TEST_VECTORS: tuple[tuple[str, str, str], ...] = (
    (
        "0000000000000000",
        "00000000000000000000",
        "82EFEDBA3336CD92",
    ),
    (
        "0000000000000000",
        "FFFFFFFFFFFFFFFFFFFF",
        "CE6E5005CF04E426",
    ),
    (
        "FFFFFFFFFFFFFFFF",
        "00000000000000000000",
        "480B5421D5611B60",
    ),
    (
        "FFFFFFFFFFFFFFFF",
        "FFFFFFFFFFFFFFFFFFFF",
        "F752C84E84124C59",
    ),
)


def verify_test_vectors() -> list[dict[str, str | bool | int]]:
    """Execute all appendix test vectors and return structured results."""
    results: list[dict[str, str | bool | int]] = []
    for index, (plaintext_hex, key_hex, expected_hex) in enumerate(
        TEST_VECTORS, start=1
    ):
        plaintext = bytes.fromhex(plaintext_hex)
        key = bytes.fromhex(key_hex)
        expected = bytes.fromhex(expected_hex)
        cipher = SCENERY(key)
        actual = cipher.encrypt_block(plaintext)
        recovered = cipher.decrypt_block(actual)
        results.append(
            {
                "test_vector": index,
                "plaintext": plaintext_hex,
                "key": key_hex,
                "expected_ciphertext": expected_hex,
                "actual_ciphertext": actual.hex().upper(),
                "encryption_pass": actual == expected,
                "decryption_pass": recovered == plaintext,
                "recovered_plaintext": recovered.hex().upper(),
            }
        )
    return results


__all__ = [
    "BLOCK_SIZE_BYTES",
    "KEY_SIZE_BYTES",
    "NUM_ROUNDS",
    "SBOX",
    "SCENERY",
    "SceneryError",
    "RoundTrace",
    "sub_columns",
    "mix_columns",
    "round_function",
    "update_key_state",
    "generate_round_keys",
    "encrypt_block",
    "decrypt_block",
    "TEST_VECTORS",
    "verify_test_vectors",
]
