import math

def to_bytes(x: int, length: int) -> bytes:
    return x.to_bytes(length, byteorder='big')

def from_bytes(b: bytes) -> int:
    return int.from_bytes(b, byteorder='big')

def sig_to_array(sig: bytes, n: int) -> list[bytes]:
    return [sig[i:i+n] for i in range(0, len(sig), n)]

def auth_path_to_array(auth_path: bytes, n: int) -> list[bytes]:
    return [auth_path[i:i+n] for i in range(0, len(auth_path), n)]

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