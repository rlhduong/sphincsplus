import math

def to_bytes(x: int, length: int) -> bytes:
    return x.to_bytes(length, byteorder='big')

def from_bytes(b: bytes) -> int:
    return int.from_bytes(b, byteorder='big')

def base_w(x: bytes, w: int, out_len: int) -> list[int]:
    base_w_digits = []
    mask = w - 1
    log_w = int(math.log2(w))
    current_byte = 0
    bits = 0
    vin = 0

    for _ in range(out_len):
        if bits == 0:
            current_byte = x[vin]
            vin += 1
            bits += 8

        bits -= log_w
        base_w_digits.append((current_byte >> bits) & mask)
    
    return base_w_digits