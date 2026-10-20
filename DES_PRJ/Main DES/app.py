"""Giao diện đồ họa tiếng Việt cho chương trình DES."""

from __future__ import annotations

import tkinter as tk
from pathlib import Path
from time import perf_counter
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText

from attack_demo import build_attack_report
from des.data import decrypt_data, decrypt_file, encrypt_data, encrypt_file
from des.formats import bytes_to_hex, bytes_to_text, parse_hex, parse_key, parse_plaintext
from tests import build_test_report


class DESApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Thuật toán DES - Mã hóa và giải mã")
        self.geometry("1040x760")
        self.minsize(900, 650)

        self._configure_style()
        self._build_header()
        self._build_tabs()

    def _configure_style(self) -> None:
        style = ttk.Style(self)
        if "vista" in style.theme_names():
            style.theme_use("vista")
        style.configure("Title.TLabel", font=("Segoe UI", 18, "bold"))
        style.configure("Subtitle.TLabel", font=("Segoe UI", 10))
        style.configure("Section.TLabelframe.Label", font=("Segoe UI", 10, "bold"))
        style.configure("TButton", padding=(10, 6))
        style.configure("Primary.TButton", font=("Segoe UI", 10, "bold"), padding=(12, 8))

    def _build_header(self) -> None:
        header = ttk.Frame(self, padding=(18, 14, 18, 8))
        header.pack(fill="x")

        ttk.Label(header, text="DES", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            header,
            text=(
                "Cài đặt DES bằng Python"
            ),
            style="Subtitle.TLabel",
        ).pack(anchor="w", pady=(4, 0))

    def _build_tabs(self) -> None:
        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=18, pady=(6, 18))

        self.text_tab = ttk.Frame(notebook, padding=14)
        self.file_tab = ttk.Frame(notebook, padding=14)
        self.test_tab = ttk.Frame(notebook, padding=14)
        self.attack_tab = ttk.Frame(notebook, padding=14)

        notebook.add(self.text_tab, text="Mã hóa / Giải mã")
        notebook.add(self.file_tab, text="Mã hóa tệp")
        notebook.add(self.test_tab, text="Kiểm thử")
        notebook.add(self.attack_tab, text="Demo tấn công")

        self._build_text_tab()
        self._build_file_tab()
        self._build_report_tab(
            self.test_tab,
            "Bộ kiểm thử",
            "Đối chiếu test vector chuẩn và chạy các ca kiểm thử tự viết.",
            "Chạy kiểm thử",
            self._run_tests,
            "test_output",
        )
        self._build_attack_tab()

    # ------------------------------------------------------------------
    # Tab mã hóa / giải mã
    # ------------------------------------------------------------------
    def _build_text_tab(self) -> None:
        self.text_tab.columnconfigure(0, weight=1)
        self.text_tab.rowconfigure(3, weight=1)

        input_frame = ttk.LabelFrame(
            self.text_tab,
            text="1. Bản rõ",
            padding=12,
            style="Section.TLabelframe",
        )
        input_frame.grid(row=0, column=0, sticky="ew")
        input_frame.columnconfigure(0, weight=1)

        mode_row = ttk.Frame(input_frame)
        mode_row.grid(row=0, column=0, sticky="w", pady=(0, 8))
        ttk.Label(mode_row, text="Kiểu nhập:").pack(side="left")

        self.plain_mode = tk.StringVar(value="text")
        ttk.Radiobutton(
            mode_row,
            text="Văn bản (Text)",
            variable=self.plain_mode,
            value="text",
            command=self._update_plain_help,
        ).pack(side="left", padx=(10, 8))
        ttk.Radiobutton(
            mode_row,
            text="HEX",
            variable=self.plain_mode,
            value="hex",
            command=self._update_plain_help,
        ).pack(side="left")

        self.plain_input = ScrolledText(input_frame, height=5, wrap="word", font=("Consolas", 10))
        self.plain_input.grid(row=1, column=0, sticky="ew")
        self.plain_input.insert("1.0", "ABCDEFGH")

        self.plain_help = ttk.Label(input_frame, style="Subtitle.TLabel")
        self.plain_help.grid(row=2, column=0, sticky="w", pady=(7, 0))
        self._update_plain_help()

        key_frame = ttk.LabelFrame(
            self.text_tab,
            text="2. Khóa DES",
            padding=12,
            style="Section.TLabelframe",
        )
        key_frame.grid(row=1, column=0, sticky="ew", pady=(12, 0))
        key_frame.columnconfigure(1, weight=1)

        ttk.Label(key_frame, text="Kiểu khóa:").grid(row=0, column=0, sticky="w")
        self.key_mode = tk.StringVar(value="text")
        key_modes = ttk.Frame(key_frame)
        key_modes.grid(row=0, column=1, sticky="w")
        ttk.Radiobutton(
            key_modes,
            text="Văn bản (Text)",
            variable=self.key_mode,
            value="text",
            command=self._update_key_help,
        ).pack(side="left")
        ttk.Radiobutton(
            key_modes,
            text="HEX",
            variable=self.key_mode,
            value="hex",
            command=self._update_key_help,
        ).pack(side="left", padx=(10, 0))

        ttk.Label(key_frame, text="Khóa:").grid(row=1, column=0, sticky="w", pady=(10, 0))
        self.key_entry = ttk.Entry(key_frame, font=("Consolas", 10))
        self.key_entry.grid(row=1, column=1, sticky="ew", padx=(10, 0), pady=(10, 0))
        self.key_entry.insert(0, "8byteKEY")

        self.key_help = ttk.Label(key_frame, style="Subtitle.TLabel")
        self.key_help.grid(row=2, column=1, sticky="w", padx=(10, 0), pady=(6, 0))
        self._update_key_help()

        button_row = ttk.Frame(self.text_tab)
        button_row.grid(row=2, column=0, sticky="ew", pady=12)
        ttk.Button(
            button_row,
            text="Mã hóa + kiểm tra giải mã",
            style="Primary.TButton",
            command=self._encrypt_text,
        ).pack(side="left")
        ttk.Button(
            button_row,
            text="Giải mã bản mã HEX",
            command=self._decrypt_ciphertext,
        ).pack(side="left", padx=8)
        ttk.Button(button_row, text="Nạp ví dụ cho trước", command=self._load_standard_example).pack(
            side="left"
        )
        ttk.Button(button_row, text="Xóa kết quả", command=self._clear_text_results).pack(side="right")

        result_frame = ttk.LabelFrame(
            self.text_tab,
            text="3. Kết quả",
            padding=12,
            style="Section.TLabelframe",
        )
        result_frame.grid(row=3, column=0, sticky="nsew")
        result_frame.columnconfigure(1, weight=1)
        result_frame.rowconfigure(3, weight=1)

        ttk.Label(result_frame, text="Bản mã (HEX):").grid(row=0, column=0, sticky="nw")
        self.cipher_input = ScrolledText(result_frame, height=3, wrap="word", font=("Consolas", 10))
        self.cipher_input.grid(row=0, column=1, sticky="ew", padx=(10, 0))

        ttk.Label(result_frame, text="Bản rõ sau giải mã:").grid(row=1, column=0, sticky="nw", pady=(10, 0))
        self.recovered_display = ScrolledText(result_frame, height=3, wrap="word", font=("Consolas", 10))
        self.recovered_display.grid(row=1, column=1, sticky="ew", padx=(10, 0), pady=(10, 0))

        ttk.Label(result_frame, text="Bản rõ dạng HEX:").grid(row=2, column=0, sticky="nw", pady=(10, 0))
        self.recovered_hex = ScrolledText(result_frame, height=2, wrap="word", font=("Consolas", 10))
        self.recovered_hex.grid(row=2, column=1, sticky="ew", padx=(10, 0), pady=(10, 0))

        self.text_status = ttk.Label(result_frame, text="Sẵn sàng.")
        self.text_status.grid(row=3, column=0, columnspan=2, sticky="sw", pady=(12, 0))

    def _update_plain_help(self) -> None:
        if self.plain_mode.get() == "text":
            text = "Text được mã hóa UTF-8. Tổng số byte của bản rõ phải là bội số của 8."
        else:
            text = "HEX: mỗi 2 ký tự biểu diễn 1 byte. Có thể chèn khoảng trắng giữa các byte."
        self.plain_help.config(text=text)

    def _update_key_help(self) -> None:
        if self.key_mode.get() == "text":
            text = "Khóa Text phải dài đúng 8 byte UTF-8, ví dụ: 8byteKEY"
        else:
            text = "Khóa HEX phải có đúng 16 ký tự HEX, ví dụ: 133457799BBCDFF1"
        self.key_help.config(text=text)

    def _get_plaintext(self) -> bytes:
        raw = self.plain_input.get("1.0", "end-1c")
        return parse_plaintext(raw, self.plain_mode.get())

    def _get_key(self) -> bytes:
        return parse_key(self.key_entry.get(), self.key_mode.get())

    def _encrypt_text(self) -> None:
        try:
            plaintext = self._get_plaintext()
            key = self._get_key()
            start = perf_counter()
            ciphertext = encrypt_data(plaintext, key)
            encrypt_time = perf_counter() - start

            start = perf_counter()
            recovered = decrypt_data(ciphertext, key)
            decrypt_time = perf_counter() - start

            self._replace_text(self.cipher_input, bytes_to_hex(ciphertext))
            self._show_recovered(recovered)

            matched = recovered == plaintext
            self.text_status.config(
                text=(
                    f"Mã hóa: {len(plaintext)} byte → {len(ciphertext)} byte | "
                    f"{encrypt_time * 1000:.3f} ms.  "
                    f"Giải mã: {decrypt_time * 1000:.3f} ms | "
                    f"Khớp bản rõ: {'Có' if matched else 'Không'}."
                )
            )
        except ValueError as exc:
            messagebox.showerror("Dữ liệu chưa hợp lệ", str(exc), parent=self)

    def _decrypt_ciphertext(self) -> None:
        try:
            ciphertext = parse_hex(self.cipher_input.get("1.0", "end-1c"), "Bản mã")
            key = self._get_key()
            start = perf_counter()
            recovered = decrypt_data(ciphertext, key)
            decrypt_time = perf_counter() - start
            self._show_recovered(recovered)
            self.text_status.config(
                text=(
                    f"Giải mã thành công {len(ciphertext)} byte bản mã | "
                    f"Thời gian: {decrypt_time * 1000:.3f} ms."
                )
            )
        except ValueError as exc:
            messagebox.showerror("Dữ liệu chưa hợp lệ", str(exc), parent=self)

    def _show_recovered(self, recovered: bytes) -> None:
        if self.plain_mode.get() == "hex":
            display = bytes_to_hex(recovered)
        else:
            display = bytes_to_text(recovered)
        self._replace_text(self.recovered_display, display)
        self._replace_text(self.recovered_hex, bytes_to_hex(recovered))

    def _load_standard_example(self) -> None:
        self.plain_mode.set("hex")
        self.key_mode.set("hex")
        self._update_plain_help()
        self._update_key_help()

        self._replace_text(self.plain_input, "0123456789ABCDEF")
        self.key_entry.delete(0, "end")
        self.key_entry.insert(0, "133457799BBCDFF1")
        self._clear_text_results()
        self.text_status.config(
            text="Ví dụ chuẩn đã được nạp. Kết quả mã hóa đúng là 85E813540F0AB405."
        )

    def _clear_text_results(self) -> None:
        self._replace_text(self.cipher_input, "")
        self._replace_text(self.recovered_display, "")
        self._replace_text(self.recovered_hex, "")
        self.text_status.config(text="Sẵn sàng.")

    @staticmethod
    def _replace_text(widget: ScrolledText, value: str) -> None:
        widget.delete("1.0", "end")
        widget.insert("1.0", value)

    # ------------------------------------------------------------------
    # Tab tệp
    # ------------------------------------------------------------------
    def _build_file_tab(self) -> None:
        self.file_tab.columnconfigure(0, weight=1)
        self.file_tab.rowconfigure(3, weight=1)

        note = ttk.Label(
            self.file_tab,
            text="Tệp được chia thành các khối 8 byte. Kích thước tệp phải là bội số của 8 byte.",
            style="Subtitle.TLabel",
        )
        note.grid(row=0, column=0, sticky="w", pady=(0, 10))

        key_frame = ttk.LabelFrame(
            self.file_tab,
            text="Khóa DES dùng cho tệp",
            padding=12,
            style="Section.TLabelframe",
        )
        key_frame.grid(row=1, column=0, sticky="ew")
        key_frame.columnconfigure(2, weight=1)

        self.file_key_mode = tk.StringVar(value="text")
        ttk.Label(key_frame, text="Kiểu khóa:").grid(row=0, column=0, sticky="w")
        ttk.Radiobutton(
            key_frame, text="Text", variable=self.file_key_mode, value="text"
        ).grid(row=0, column=1, sticky="w", padx=(10, 6))
        ttk.Radiobutton(
            key_frame, text="HEX", variable=self.file_key_mode, value="hex"
        ).grid(row=0, column=2, sticky="w")

        ttk.Label(key_frame, text="Khóa:").grid(row=1, column=0, sticky="w", pady=(10, 0))
        self.file_key_entry = ttk.Entry(key_frame, font=("Consolas", 10))
        self.file_key_entry.grid(row=1, column=1, columnspan=2, sticky="ew", padx=(10, 0), pady=(10, 0))
        self.file_key_entry.insert(0, "8byteKEY")

        actions = ttk.Frame(self.file_tab)
        actions.grid(row=2, column=0, sticky="ew", pady=12)
        actions.columnconfigure(0, weight=1)
        actions.columnconfigure(1, weight=1)

        enc = ttk.LabelFrame(actions, text="Mã hóa tệp", padding=12, style="Section.TLabelframe")
        dec = ttk.LabelFrame(actions, text="Giải mã tệp", padding=12, style="Section.TLabelframe")
        enc.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        dec.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        enc.columnconfigure(0, weight=1)
        dec.columnconfigure(0, weight=1)

        self.enc_source = tk.StringVar()
        self.enc_output = tk.StringVar()
        self.dec_source = tk.StringVar()
        self.dec_output = tk.StringVar()

        self._file_path_row(enc, "Tệp nguồn:", self.enc_source, self._choose_encrypt_source, 0)
        self._file_path_row(enc, "Tệp đầu ra:", self.enc_output, self._choose_encrypt_output, 1)
        ttk.Button(enc, text="Mã hóa tệp", style="Primary.TButton", command=self._encrypt_file).grid(
            row=2, column=0, sticky="w", pady=(12, 0)
        )

        self._file_path_row(dec, "Tệp .des:", self.dec_source, self._choose_decrypt_source, 0)
        self._file_path_row(dec, "Tệp đầu ra:", self.dec_output, self._choose_decrypt_output, 1)
        ttk.Button(dec, text="Giải mã tệp", style="Primary.TButton", command=self._decrypt_file).grid(
            row=2, column=0, sticky="w", pady=(12, 0)
        )

        log_frame = ttk.LabelFrame(
            self.file_tab,
            text="Kết quả xử lý tệp",
            padding=10,
            style="Section.TLabelframe",
        )
        log_frame.grid(row=3, column=0, sticky="nsew")
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        self.file_log = ScrolledText(log_frame, height=9, wrap="word", font=("Consolas", 10))
        self.file_log.grid(row=0, column=0, sticky="nsew")

    @staticmethod
    def _file_path_row(
        parent: ttk.LabelFrame,
        label: str,
        variable: tk.StringVar,
        command,
        row: int,
    ) -> None:
        frame = ttk.Frame(parent)
        frame.grid(row=row, column=0, sticky="ew", pady=(0, 8))
        frame.columnconfigure(1, weight=1)
        ttk.Label(frame, text=label, width=11).grid(row=0, column=0, sticky="w")
        ttk.Entry(frame, textvariable=variable).grid(row=0, column=1, sticky="ew", padx=(6, 6))
        ttk.Button(frame, text="Chọn...", command=command).grid(row=0, column=2)

    def _get_file_key(self) -> bytes:
        return parse_key(self.file_key_entry.get(), self.file_key_mode.get())

    def _choose_encrypt_source(self) -> None:
        path = filedialog.askopenfilename(title="Chọn tệp cần mã hóa")
        if path:
            self.enc_source.set(path)
            if not self.enc_output.get():
                self.enc_output.set(path + ".des")

    def _choose_encrypt_output(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Chọn nơi lưu bản mã",
            defaultextension=".des",
            filetypes=[("Tệp DES", "*.des"), ("Tất cả tệp", "*.*")],
        )
        if path:
            self.enc_output.set(path)

    def _choose_decrypt_source(self) -> None:
        path = filedialog.askopenfilename(
            title="Chọn tệp cần giải mã",
            filetypes=[("Tệp DES", "*.des"), ("Tất cả tệp", "*.*")],
        )
        if path:
            self.dec_source.set(path)
            if not self.dec_output.get():
                p = Path(path)
                name = p.name[:-4] if p.name.lower().endswith(".des") else p.name
                original = Path(name)
                if original.suffix:
                    output_name = f"{original.stem}_decrypted{original.suffix}"
                else:
                    output_name = f"{original.name}_decrypted"
                self.dec_output.set(str(p.with_name(output_name)))

    def _choose_decrypt_output(self) -> None:
        path = filedialog.asksaveasfilename(title="Chọn nơi lưu tệp sau giải mã")
        if path:
            self.dec_output.set(path)

    def _encrypt_file(self) -> None:
        try:
            src = self.enc_source.get().strip()
            dst = self.enc_output.get().strip()
            if not src or not dst:
                raise ValueError("Cần chọn đầy đủ tệp nguồn và tệp đầu ra.")
            key = self._get_file_key()
            start = perf_counter()
            count = encrypt_file(src, dst, key)
            elapsed = perf_counter() - start
            self._append_file_log(
                f"Mã hóa thành công: {src}\n→ {dst}\n"
                f"Đã xử lý: {count} byte\nThời gian: {elapsed:.6f} giây\n"
            )
        except (ValueError, OSError) as exc:
            messagebox.showerror("Không thể mã hóa tệp", str(exc), parent=self)

    def _decrypt_file(self) -> None:
        try:
            src = self.dec_source.get().strip()
            dst = self.dec_output.get().strip()
            if not src or not dst:
                raise ValueError("Cần chọn đầy đủ tệp nguồn và tệp đầu ra.")
            key = self._get_file_key()
            start = perf_counter()
            count = decrypt_file(src, dst, key)
            elapsed = perf_counter() - start
            self._append_file_log(
                f"Giải mã thành công: {src}\n→ {dst}\n"
                f"Đã xử lý: {count} byte\nThời gian: {elapsed:.6f} giây\n"
            )
        except (ValueError, OSError) as exc:
            messagebox.showerror("Không thể giải mã tệp", str(exc), parent=self)

    def _append_file_log(self, text: str) -> None:
        self.file_log.insert("end", text + "\n")
        self.file_log.see("end")

    # ------------------------------------------------------------------
    # Các tab báo cáo
    # ------------------------------------------------------------------
    def _build_report_tab(
        self,
        parent: ttk.Frame,
        title: str,
        description: str,
        button_text: str,
        command,
        attr_name: str,
    ) -> None:
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(2, weight=1)

        ttk.Label(parent, text=title, style="Title.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(parent, text=description, style="Subtitle.TLabel").grid(
            row=1, column=0, sticky="w", pady=(4, 10)
        )

        box = ScrolledText(parent, wrap="word", font=("Consolas", 10))
        box.grid(row=2, column=0, sticky="nsew")
        setattr(self, attr_name, box)

        ttk.Button(parent, text=button_text, style="Primary.TButton", command=command).grid(
            row=3, column=0, sticky="w", pady=(10, 0)
        )

    def _build_attack_tab(self) -> None:
        self.attack_tab.columnconfigure(0, weight=1)
        self.attack_tab.rowconfigure(3, weight=1)

        ttk.Label(
            self.attack_tab,
            text="Minh họa tấn công brute-force",
            style="Title.TLabel",
        ).grid(row=0, column=0, sticky="w")

        explanation = (
            "Tình huống: Người tấn công đã biết bản rõ ATTACK!! và bản mã tương ứng, nhưng chưa biết "
            "khóa. Vì vậy chương trình sẽ thử từng khóa lần lượt 4096 giá trị từ 000 đến FFF.\n"
            "Cách chạy: với mỗi khóa, chương trình mã hóa bản rõ đã biết rồi so sánh kết quả với bản mã mục tiêu"
            "Khi hai bản mã trùng nhau, quá trình dừng và hiển thị khóa tìm được."
        )
        ttk.Label(
            self.attack_tab,
            text=explanation,
            style="Subtitle.TLabel",
            wraplength=950,
            justify="left",
        ).grid(row=1, column=0, sticky="w", pady=(6, 10))

        ttk.Button(
            self.attack_tab,
            text="Chạy minh họa",
            style="Primary.TButton",
            command=self._run_attack,
        ).grid(row=2, column=0, sticky="w", pady=(0, 10))

        self.attack_output = ScrolledText(
            self.attack_tab, wrap="word", font=("Consolas", 10)
        )
        self.attack_output.grid(row=3, column=0, sticky="nsew")

    def _run_tests(self) -> None:
        _, report = build_test_report()
        self._replace_text(self.test_output, report)

    def _run_attack(self) -> None:
        self._replace_text(self.attack_output, "Đang chạy...\n")
        self.update_idletasks()
        self._replace_text(self.attack_output, build_attack_report())


def main() -> None:
    app = DESApp()
    app.mainloop()


if __name__ == "__main__":
    main()
