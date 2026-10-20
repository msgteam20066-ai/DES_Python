"""Bộ kiểm thử DES: test vector chuẩn và 3 ca kiểm thử tự viết đơn giản."""

from time import perf_counter

from des.core import decrypt_block, encrypt_block
from des.data import decrypt_data, encrypt_data


def _line(name: str, ok: bool, detail: str = "") -> str:
    status = "PASS" if ok else "FAIL"
    base = f"[{status}] {name}"
    return base if not detail else f"{base}\n       {detail}"


def build_test_report() -> tuple[bool, str]:
    lines: list[str] = []
    all_ok = True
    suite_start = perf_counter()

    # Các vector chuẩn: đầu vào và đầu ra đúng đã biết trước.
    lines.append("=== ĐỐI CHIẾU TEST VECTOR DES ===")
    vectors = [
        ("NIST 1", "0101010101010101", "8000000000000000", "95F8A5E5DD31D900"),
        ("NIST 2", "0101010101010101", "4000000000000000", "DD7F121CA5015619"),
        ("NIST 3", "0101010101010101", "2000000000000000", "2E8653104F3834EA"),
        ("Ví dụ cho trước", "133457799BBCDFF1", "0123456789ABCDEF", "85E813540F0AB405"),
    ]

    for name, key_hex, plain_hex, expected_hex in vectors:
        key = bytes.fromhex(key_hex)
        plaintext = bytes.fromhex(plain_hex)
        expected = bytes.fromhex(expected_hex)

        start = perf_counter()
        actual = encrypt_block(plaintext, key)
        recovered = decrypt_block(actual, key)
        elapsed = perf_counter() - start

        ok = actual == expected and recovered == plaintext
        all_ok &= ok
        lines.append(
            _line(
                name,
                ok,
                f"P={plain_hex}  K={key_hex}\n"
                f"       Expected={expected_hex}\n"
                f"       Actual  ={actual.hex().upper()}\n"
                f"       Thời gian mã hóa + giải mã: {elapsed * 1000:.3f} ms",
            )
        )

    # Ba ca tự viết chỉ dùng ASCII để dễ quan sát số byte và số khối.
    lines.append("\n=== 3 CA KIỂM THỬ TỰ VIẾT ===")
    key = b"12345678"
    cases = [
        ("Ca 1 - 1 khối", b"ABCDEFGH"),
        ("Ca 2 - 2 khối", b"ABCDEFGHIJKLMNOP"),
        ("Ca 3 - 3 khối", b"ABCDEFGHIJKLMNOPQRSTUVWX"),
    ]

    for name, plaintext in cases:
        start = perf_counter()
        ciphertext = encrypt_data(plaintext, key)
        recovered = decrypt_data(ciphertext, key)
        elapsed = perf_counter() - start

        ok = recovered == plaintext and len(ciphertext) == len(plaintext)
        all_ok &= ok
        blocks = len(plaintext) // 8
        lines.append(
            _line(
                name,
                ok,
                f"Plaintext={plaintext.decode('ascii')} | {len(plaintext)} byte = {blocks} block\n"
                f"       Khóa=12345678 | Giải mã khớp bản rõ: {'Có' if recovered == plaintext else 'Không'}\n"
                f"       Thời gian mã hóa + giải mã: {elapsed * 1000:.3f} ms",
            )
        )

    total = perf_counter() - suite_start
    lines.append("\n=== KẾT LUẬN ===")
    lines.append("TẤT CẢ TEST ĐỀU PASS." if all_ok else "CÓ TEST BỊ FAIL.")
    lines.append(f"Tổng thời gian chạy bộ kiểm thử: {total:.6f} giây")
    return all_ok, "\n".join(lines)


def run_all_tests() -> bool:
    ok, report = build_test_report()
    print(report)
    return ok


if __name__ == "__main__":
    raise SystemExit(0 if run_all_tests() else 1)
