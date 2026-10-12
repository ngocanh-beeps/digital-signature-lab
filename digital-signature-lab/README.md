# digital-signature-lab — Phần của Ánh

Tài liệu này hướng dẫn cài đặt và chạy các module chữ ký số (DSA, ECDSA,
Ed25519) và dữ liệu demo nonce-reuse cho ECDSA.

## 1. Yêu cầu

```
pip install cryptography
```

(Tùy chọn, để chạy test có cấu trúc đẹp hơn: `pip install pytest`.
Không bắt buộc — có thể chạy test bằng `python3` thuần như bên dưới.)

## 2. Cấu trúc thư mục

```
digital-signature-lab/
├── src/
│   └── signatures/
│       ├── dsa.py        # DSA chuẩn — generate_keypair / sign / verify
│       ├── ecdsa.py       # ECDSA chuẩn (k ngẫu nhiên nội bộ, AN TOÀN)
│       └── ed25519.py     # Ed25519 chuẩn
├── demos/
│   └── d2_ecdsa_nonce/
│       ├── ecdsa_fixed_k.py        # ECDSA CỐ Ý LỖI — cho phép truyền k. CHỈ dùng demo.
│       ├── generate_demo_data.py   # Script của Ánh: tạo 2 chữ ký dùng chung k
│       ├── public_handoff.json     # Dữ liệu công khai bàn giao cho My
│       └── _answer_key_DO_NOT_SHARE.json  # Đáp án riêng của Ánh, KHÔNG gửi My
└── tests/
    └── test_signatures.py
```

## 3. Giao diện chuẩn (3 hàm) mỗi thuật toán phải có

```python
generate_keypair(**params)                       -> (private_key, public_key)
sign(private_key, data: bytes, **params)          -> signature: bytes
verify(public_key, data: bytes,
       signature: bytes, **params)                -> bool
```

Đây là giao diện để chương trình tổng của Thảo gọi vào. **Không tự ý đổi
tên hoặc đổi thứ tự tham số** — nếu cần đổi, báo Thảo trước.

## 4. Chạy thử từng module

```bash
cd src/signatures
python3 dsa.py        # in "DSA module OK"
python3 ecdsa.py      # in "ECDSA module OK"
python3 ed25519.py    # in "Ed25519 module OK"
```

## 5. Chạy test đầy đủ (4 trường hợp x 3 thuật toán)

Test kiểm tra: chữ ký đúng → pass; dữ liệu bị sửa → fail; chữ ký bị sửa →
fail; sai khóa công khai → fail.

Với pytest (nếu có mạng để cài):
```bash
pytest tests/test_signatures.py -v
```

Không có pytest, chạy thuần Python:
```bash
cd digital-signature-lab
python3 -c "
import sys; sys.path.insert(0,'src/signatures')
import dsa, ecdsa, ed25519
for name, mod in [('DSA',dsa), ('ECDSA',ecdsa), ('Ed25519',ed25519)]:
    priv, pub = mod.generate_keypair()
    data = b'Hello Signature Lab'
    sig = mod.sign(priv, data)
    assert mod.verify(pub, data, sig) is True
    assert mod.verify(pub, data + b'x', sig) is False
    assert mod.verify(pub, data, sig[:-1] + bytes([sig[-1]^0xFF])) is False
    priv2, pub2 = mod.generate_keypair()
    assert mod.verify(pub2, data, sig) is False
    print(name, 'OK')
"
```

## 6. Demo 2 — ECDSA nonce reuse (phối hợp với My)

⚠️ **`demos/d2_ecdsa_nonce/ecdsa_fixed_k.py` là bản ECDSA cố ý có lỗ hổng**
(cho phép truyền `k` từ bên ngoài). Module này **tách biệt hoàn toàn** khỏi
`src/signatures/ecdsa.py` (bản chuẩn, an toàn) và **không được** dùng trong
chức năng ký file chính của hệ thống.

### Quy trình

1. Chạy:
   ```bash
   cd demos/d2_ecdsa_nonce
   python3 generate_demo_data.py
   ```
2. Script sẽ:
   - Tạo 1 cặp khóa ECDSA (khóa riêng `d` không bao giờ ghi ra file công khai).
   - Ký 2 thông điệp khác nhau (`Hello RSA Lab`, `Hello ECDSA Lab`) bằng
     **cùng một nonce `k`**.
   - Ghi dữ liệu công khai cần cho My vào `public_handoff.json`:
     khóa công khai, 2 thông điệp, 2 chữ ký `(r, s)`, tên đường cong, tên
     hàm băm.
   - Ghi riêng đáp án (`d`, `k`) vào `_answer_key_DO_NOT_SHARE.json` —
     **file này chỉ Ánh giữ**, dùng để tự đối chiếu kết quả My khôi phục
     được, không gửi cho My.
3. Gửi **chỉ** `public_handoff.json` cho My.
4. My dùng công thức toán học (từ 2 cặp `(r,s)` cùng `k`) để khôi phục `k`
   rồi `d`, sau đó tạo chữ ký giả hợp lệ bằng `d` khôi phục được —
   code của My nằm ở `demos/d2_ecdsa_nonce/attack.py`.

### Tham số đã thống nhất với My cho demo này

| Mục | Giá trị |
|---|---|
| Đường cong | secp256r1 (P-256) |
| Hàm băm | SHA-256 |
| Chuẩn hóa s (low-s) | Không áp dụng (giữ s thô để công thức tấn công đơn giản) — **xác nhận lại với My trước khi đổi** |
| Định dạng chữ ký trao đổi | JSON `{"r": int, "s": int}` (không phải DER) |

Nếu đổi bất kỳ tham số nào ở trên, phải báo lại cho My vì công thức khôi
phục khóa riêng trong `attack.py` phụ thuộc trực tiếp vào các tham số này.

## 7. Lưu ý bảo mật khi làm demo

- Không commit `_answer_key_DO_NOT_SHARE.json` lên repo chung.
- Không để lộ khóa riêng `d` hay nonce `k` cho My bằng bất kỳ cách nào khác
  ngoài việc để My tự khôi phục từ `public_handoff.json`.
- Không copy code trong `demos/d2_ecdsa_nonce/ecdsa_fixed_k.py` sang
  `src/signatures/ecdsa.py` hoặc bất kỳ đường dẫn ký file thật nào.
