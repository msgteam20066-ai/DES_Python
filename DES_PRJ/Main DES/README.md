# CÀI ĐẶT THUẬT TOÁN DES BẰNG PYTHON

## 1. Giới thiệu

Chương trình cài đặt thuật toán Data Encryption Standard (DES) bằng Python. Phần lõi DES được xây dựng trực tiếp từ các bảng hoán vị, lịch sinh khóa, hàm Feistel và các S-box; không sử dụng thư viện mật mã có sẵn cho phần mã hóa và giải mã DES.

Các chức năng chính:

- mã hóa và giải mã DES;
- nhập bản rõ theo hai dạng **Văn bản (Text)** hoặc **HEX**;
- nhập khóa theo hai dạng **Văn bản (Text)** hoặc **HEX**;
- mã hóa và giải mã tệp;
- đối chiếu với test vector chuẩn và chạy 3 ca kiểm thử tự viết;
- hiển thị thời gian thực thi ngay sau mỗi lần mã hóa, giải mã hoặc kiểm thử;
- minh họa tấn công brute-force trên phạm vi khóa thực hành;
- giao diện đồ họa bằng tiếng Việt.

DES xử lý dữ liệu theo khối 64 bit, tương đương 8 byte. Chương trình không sử dụng padding nên dữ liệu đầu vào phải có số byte là bội số của 8.

---

## 2. Yêu cầu môi trường

- Python 3.10 trở lên.
- Không cần cài thêm thư viện bằng `pip`.
- Giao diện sử dụng `tkinter`, thư viện chuẩn đi kèm Python trên Windows.

Kiểm tra Python:

```bash
python --version
```

hoặc:

```bash
py --version
```

---

## 3. Cấu trúc mã nguồn

```text
DES_Python/
├── app.py                # Giao diện đồ họa tiếng Việt
├── CHAY_CHUONG_TRINH.bat # Chạy nhanh trên Windows
├── tests.py              # Test vector chuẩn và 3 ca kiểm thử tự viết
├── attack_demo.py        # Minh họa brute-force
├── sample_data.txt       # Tệp dùng để demo
├── README.md
└── des/
    ├── __init__.py
    ├── core.py           # Phần lõi DES
    ├── data.py           # Xử lý nhiều khối và tệp
    ├── formats.py        # Chuyển đổi Text/HEX
    └── tables.py         # Các bảng IP, FP, E, P, PC-1, PC-2 và S-box
```

Phần thuật toán được tách khỏi giao diện. `core.py` thực hiện DES, còn `app.py` nhận dữ liệu từ người dùng và hiển thị kết quả.

---

## 4. Cách chạy chương trình

Trên Windows có thể nhấp đúp:

```text
CHAY_CHUONG_TRINH.bat
```

Hoặc mở Terminal trong thư mục chương trình và chạy:

```bash
python app.py
```

Nếu máy sử dụng lệnh `py`:

```bash
py app.py
```

Giao diện gồm bốn thẻ:

1. **Mã hóa / Giải mã**
2. **Mã hóa tệp**
3. **Kiểm thử**
4. **Demo tấn công**

---

## 5. Mã hóa và giải mã dữ liệu

### 5.1. Bản rõ dạng Text

Chọn **Văn bản (Text)** rồi nhập nội dung. Văn bản được chuyển thành byte UTF-8 trước khi đưa vào DES.

Ví dụ một khối 8 byte:

```text
ABCDEFGH
```

### 5.2. Bản rõ dạng HEX

Chọn **HEX**. Mỗi hai ký tự HEX biểu diễn một byte.

Ví dụ:

```text
0123456789ABCDEF
```

tương ứng với:

```text
01 23 45 67 89 AB CD EF
```

### 5.3. Khóa dạng Text

Khóa Text phải có đúng 8 byte.

Ví dụ:

```text
12345678
```

hoặc:

```text
8byteKEY
```

### 5.4. Khóa dạng HEX

Khóa HEX phải có đúng 16 ký tự HEX.

Ví dụ:

```text
133457799BBCDFF1
```

### 5.5. Ví dụ chuẩn DES

Bấm **Nạp ví dụ chuẩn DES** để điền:

```text
Bản rõ HEX: 0123456789ABCDEF
Khóa HEX:    133457799BBCDFF1
```

Kết quả:

```text
Bản mã HEX: 85E813540F0AB405
```

Chương trình đồng thời giải mã ngược bản mã để kiểm tra kết quả.

Sau mỗi lần chạy, giao diện hiển thị thời gian mã hóa và giải mã ngay tại phần kết quả.

---

## 6. Mã hóa và giải mã tệp

Trong thẻ **Mã hóa tệp**:

1. chọn kiểu khóa Text hoặc HEX;
2. nhập khóa;
3. chọn tệp nguồn;
4. chọn nơi lưu tệp đầu ra;
5. bấm **Mã hóa tệp** hoặc **Giải mã tệp**.

DES xử lý tệp theo từng khối 8 byte. Kích thước tệp phải là bội số của 8 byte.

Sau khi xử lý, chương trình hiển thị:

- đường dẫn tệp nguồn;
- đường dẫn tệp đầu ra;
- số byte đã xử lý;
- thời gian thực thi.

Tệp mã hóa là dữ liệu nhị phân nên khi mở trực tiếp bằng trình soạn thảo văn bản có thể xuất hiện các ký tự không đọc được. Tệp sau giải mã mới được dùng để đối chiếu với dữ liệu ban đầu.

---

## 7. Quy trình DES trong `core.py`

### 7.1. Sinh khóa con

Khóa 64 bit đi qua PC-1 để tạo 56 bit, sau đó tách thành hai nửa 28 bit. Hai nửa được dịch vòng trái qua 16 vòng và đi qua PC-2 để tạo 16 khóa con, mỗi khóa dài 48 bit.

### 7.2. Hoán vị đầu

Khối bản rõ 64 bit đi qua Initial Permutation (IP), sau đó chia thành:

```text
L0: 32 bit
R0: 32 bit
```

### 7.3. 16 vòng Feistel

Mỗi vòng thực hiện:

```text
Li = R(i-1)
Ri = L(i-1) XOR F(R(i-1), Ki)
```

Hàm `F` gồm:

1. mở rộng E: 32 bit → 48 bit;
2. XOR với khóa con;
3. đưa qua 8 S-box: 48 bit → 32 bit;
4. hoán vị P.

### 7.4. Hoán vị cuối

Sau vòng 16, ghép `R16L16` rồi thực hiện Final Permutation (FP) để tạo bản mã 64 bit.

### 7.5. Giải mã

DES dùng cấu trúc Feistel nên giải mã sử dụng cùng quy trình, chỉ đảo thứ tự khóa con:

```text
Mã hóa : K1, K2, ..., K16
Giải mã: K16, K15, ..., K1
```

---

## 8. Xử lý dữ liệu nhiều khối

`des/data.py` chia dữ liệu thành từng khối 8 byte và gọi DES cho từng khối:

```python
for offset in range(0, len(data), 8):
    block = data[offset:offset + 8]
    output.extend(encrypt_block(block, key))
```

Chương trình không sử dụng IV và không padding.

---

## 9. Bộ kiểm thử

Thẻ **Kiểm thử** gồm hai phần.

### 9.1. Test vector đối chiếu

Chương trình sử dụng ba vector Known-Answer Test của DES và một vector DES thường dùng trong tài liệu giảng dạy.

Ví dụ:

```text
Key       = 133457799BBCDFF1
Plaintext = 0123456789ABCDEF
Expected  = 85E813540F0AB405
```

Chương trình tự mã hóa, so sánh kết quả với `Expected`, sau đó giải mã để kiểm tra có thu lại đúng bản rõ hay không.

### 9.2. Ba ca kiểm thử tự viết

Ba ca kiểm thử được thiết kế đơn giản bằng dữ liệu ASCII và cùng khóa `12345678`:

```text
Ca 1: ABCDEFGH                 = 8 byte  = 1 block
Ca 2: ABCDEFGHIJKLMNOP         = 16 byte = 2 block
Ca 3: ABCDEFGHIJKLMNOPQRSTUVWX = 24 byte = 3 block
```

Mỗi ca thực hiện:

```text
bản rõ → mã hóa → bản mã → giải mã → bản rõ
```

Một ca được đánh dấu `PASS` khi dữ liệu sau giải mã giống dữ liệu ban đầu và độ dài bản mã bằng độ dài bản rõ.

Thời gian mã hóa và giải mã của từng ca được hiển thị ngay trong kết quả kiểm thử. Cuối cùng chương trình hiển thị tổng thời gian chạy toàn bộ bộ kiểm thử.

Có thể chạy riêng:

```bash
python tests.py
```

---

## 10. Đo thời gian thực thi

Thời gian thực thi được gắn trực tiếp với từng thao tác thay vì đặt ở một chức năng riêng.

- **Mã hóa / Giải mã:** hiển thị thời gian mã hóa và giải mã sau mỗi lần bấm chạy.
- **Mã hóa tệp / Giải mã tệp:** hiển thị thời gian xử lý của tệp vừa chọn.
- **Kiểm thử:** hiển thị thời gian của từng test và tổng thời gian của bộ kiểm thử.
- **Demo brute-force:** hiển thị thời gian tìm khóa và tốc độ thử khóa.

Thời gian được đo bằng `time.perf_counter()` của Python.

---

## 11. Minh họa tấn công brute-force

Thẻ **Demo tấn công** trình bày tình huống và cách chạy ngay phía dưới tiêu đề.

Tình huống minh họa:

- đã biết bản rõ `ATTACK!!`;
- đã có bản mã mục tiêu tương ứng;
- chưa biết giá trị khóa ứng viên cần tìm.

Chương trình thử lần lượt 4096 giá trị ứng viên từ `000` đến `FFF`. Với mỗi ứng viên:

```text
ứng viên khóa
    ↓
tạo khóa DES 8 byte
    ↓
mã hóa ATTACK!!
    ↓
so sánh với bản mã mục tiêu
    ↓
trùng: dừng và báo khóa
khác: thử ứng viên tiếp theo
```

Khi bấm **Chạy minh họa**, chương trình hiển thị:

- bản rõ đã biết;
- bản mã mục tiêu;
- số khóa đã thử;
- thời gian thực thi;
- tốc độ thử khóa;
- khóa ứng viên tìm được.

Có thể chạy riêng:

```bash
python attack_demo.py
```

---

## 12. Tệp mã nguồn chính

### `des/core.py`

Chứa phần cài đặt DES:

- hoán vị bit;
- sinh khóa con;
- hàm Feistel;
- mã hóa một block;
- giải mã một block.

### `des/tables.py`

Chứa các bảng cố định của DES:

- IP, FP;
- E, P;
- PC-1, PC-2;
- lịch dịch trái;
- 8 S-box.

### `des/formats.py`

Chuyển đổi dữ liệu người dùng nhập:

- Text → bytes;
- HEX → bytes.

### `des/data.py`

Chia dữ liệu dài thành các khối 8 byte và xử lý tệp.

### `app.py`

Xây dựng giao diện và gọi các module DES. Phần thuật toán không phụ thuộc vào giao diện.

---

## 13. Tài liệu đối chiếu

- FIPS PUB 46-3, *Data Encryption Standard (DES)*.
- NIST SP 800-17, *Modes of Operation Validation System (MOVS): Requirements and Procedures*.
- Các tài liệu giảng dạy DES sử dụng vector `0123456789ABCDEF / 133457799BBCDFF1`.
