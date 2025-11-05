import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import os
import random
from sympy import isprime, randprime, mod_inverse
import math


class RSAApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Асимметричная криптография - RSA (Вариант 4)")
        self.root.geometry("900x700")

        # Переменные для ключей
        self.public_key = None
        self.private_key = None
        self.n = None

        # Переменные состояния
        self.current_file = None
        self.processed_data = None

        self.create_widgets()

    def create_widgets(self):
        """Создание элементов интерфейса"""
        # Заголовок
        title_label = tk.Label(self.root, text="Асимметричная криптография - Алгоритм RSA",
                               font=("Arial", 14, "bold"))
        title_label.pack(pady=10)

        # Создание вкладок
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)

        # Вкладка генерации ключей
        key_frame = ttk.Frame(notebook)
        notebook.add(key_frame, text="Генерация ключей")

        # Вкладка шифрования/дешифрования
        crypto_frame = ttk.Frame(notebook)
        notebook.add(crypto_frame, text="Шифрование/Дешифрование")

        self.setup_key_tab(key_frame)
        self.setup_crypto_tab(crypto_frame)

        # Статус бар
        self.status_var = tk.StringVar()
        self.status_var.set("Готов к работе")
        status_bar = tk.Label(self.root, textvariable=self.status_var, bd=1,
                              relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def setup_key_tab(self, parent):
        """Настройка вкладки генерации ключей"""
        # Параметры генерации
        param_frame = tk.LabelFrame(parent, text="Параметры генерации", padx=10, pady=10)
        param_frame.pack(fill='x', padx=10, pady=5)

        tk.Label(param_frame, text="Битовая длина простых чисел (минимум 32 бита):").grid(row=0, column=0, sticky='w',
                                                                                          pady=2)
        self.bit_length_var = tk.StringVar(value="32")
        bit_length_entry = tk.Entry(param_frame, textvariable=self.bit_length_var, width=10)
        bit_length_entry.grid(row=0, column=1, sticky='w', pady=2)

        # Кнопки генерации
        button_frame = tk.Frame(parent)
        button_frame.pack(fill='x', padx=10, pady=10)

        self.btn_generate_primes = tk.Button(button_frame, text="Сгенерировать простые числа",
                                             command=self.generate_primes, padx=10, pady=5, bg="lightblue")
        self.btn_generate_primes.pack(side=tk.LEFT, padx=5)

        self.btn_generate_keys = tk.Button(button_frame, text="Сгенерировать ключи",
                                           command=self.generate_keys, padx=10, pady=5, bg="lightgreen")
        self.btn_generate_keys.pack(side=tk.LEFT, padx=5)

        # Область вывода ключей
        key_output_frame = tk.LabelFrame(parent, text="Сгенерированные ключи", padx=10, pady=10)
        key_output_frame.pack(fill='both', expand=True, padx=10, pady=5)

        # Простые числа
        tk.Label(key_output_frame, text="Простые числа:").grid(row=0, column=0, sticky='w', pady=2)
        self.primes_text = scrolledtext.ScrolledText(key_output_frame, width=80, height=3)
        self.primes_text.grid(row=1, column=0, columnspan=2, sticky='nsew', pady=5)

        # Открытый ключ
        tk.Label(key_output_frame, text="Открытый ключ (e, n):").grid(row=2, column=0, sticky='w', pady=2)
        self.public_key_text = scrolledtext.ScrolledText(key_output_frame, width=80, height=2)
        self.public_key_text.grid(row=3, column=0, columnspan=2, sticky='nsew', pady=5)

        # Закрытый ключ
        tk.Label(key_output_frame, text="Закрытый ключ (d, n):").grid(row=4, column=0, sticky='w', pady=2)
        self.private_key_text = scrolledtext.ScrolledText(key_output_frame, width=80, height=2)
        self.private_key_text.grid(row=5, column=0, columnspan=2, sticky='nsew', pady=5)

        key_output_frame.columnconfigure(0, weight=1)
        key_output_frame.rowconfigure(1, weight=1)
        key_output_frame.rowconfigure(3, weight=1)
        key_output_frame.rowconfigure(5, weight=1)

    def setup_crypto_tab(self, parent):
        """Настройка вкладки шифрования/дешифрования"""
        # Файловые операции
        file_frame = tk.LabelFrame(parent, text="Работа с файлами", padx=10, pady=10)
        file_frame.pack(fill='x', padx=10, pady=5)

        file_buttons_frame = tk.Frame(file_frame)
        file_buttons_frame.pack(fill='x', pady=5)

        self.btn_select_file = tk.Button(file_buttons_frame, text="Выбрать файл",
                                         command=self.select_file, padx=10, pady=5, bg="lightyellow")
        self.btn_select_file.pack(side=tk.LEFT, padx=5)

        self.btn_encrypt = tk.Button(file_buttons_frame, text="Зашифровать",
                                     command=self.encrypt_file, padx=10, pady=5, bg="lightgreen")
        self.btn_encrypt.pack(side=tk.LEFT, padx=5)

        self.btn_decrypt = tk.Button(file_buttons_frame, text="Расшифровать",
                                     command=self.decrypt_file, padx=10, pady=5, bg="lightcoral")
        self.btn_decrypt.pack(side=tk.LEFT, padx=5)

        self.btn_save_result = tk.Button(file_buttons_frame, text="Сохранить результат",
                                         command=self.save_result, padx=10, pady=5, bg="lightblue")
        self.btn_save_result.pack(side=tk.LEFT, padx=5)

        # Информация о файле
        info_frame = tk.LabelFrame(parent, text="Информация о файле и процессе", padx=10, pady=10)
        info_frame.pack(fill='both', expand=True, padx=10, pady=5)

        self.file_info_text = scrolledtext.ScrolledText(info_frame, width=80, height=15)
        self.file_info_text.pack(fill='both', expand=True)

        # Прогресс бар
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(parent, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill='x', padx=10, pady=5)

    def generate_primes(self):
        """Генерация простых чисел с использованием готовых библиотек"""
        try:
            bit_length = int(self.bit_length_var.get())
            if bit_length < 32:
                messagebox.showwarning("Предупреждение", "Минимальная битовая длина - 32 бита")
                return

            self.status_var.set("Генерация простых чисел...")
            self.root.update()

            # Генерация двух простых чисел с помощью sympy
            p = randprime(2 ** (bit_length - 1), 2 ** bit_length)
            q = randprime(2 ** (bit_length - 1), 2 ** bit_length)

            # Убедимся, что p и q разные
            while p == q:
                q = randprime(2 ** (bit_length - 1), 2 ** bit_length)

            self.primes_text.delete(1.0, tk.END)
            self.primes_text.insert(tk.END, f"p = {p}\n")
            self.primes_text.insert(tk.END, f"q = {q}\n")
            self.primes_text.insert(tk.END, f"Длина p: {p.bit_length()} бит\n")
            self.primes_text.insert(tk.END, f"Длина q: {q.bit_length()} бит\n")

            self.p_value = p
            self.q_value = q

            self.status_var.set("Простые числа сгенерированы")

        except ValueError:
            messagebox.showerror("Ошибка", "Введите корректную битовую длину")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при генерации простых чисел: {str(e)}")

    def generate_keys(self):
        """Генерация пары ключей RSA"""
        if not hasattr(self, 'p_value') or not hasattr(self, 'q_value'):
            messagebox.showwarning("Предупреждение", "Сначала сгенерируйте простые числа")
            return

        try:
            self.status_var.set("Генерация ключей...")
            self.root.update()

            p = self.p_value
            q = self.q_value

            # Вычисление n и φ(n)
            n = p * q
            phi = (p - 1) * (q - 1)

            # Выбор открытой экспоненты e (взаимно простой с φ(n))
            e = 65537  # Стандартное значение
            while math.gcd(e, phi) != 1:
                e = random.randint(2, phi - 1)

            # Вычисление закрытой экспоненты d
            d = mod_inverse(e, phi)

            # Сохранение ключей
            self.public_key = (e, n)
            self.private_key = (d, n)
            self.n = n

            # Вывод ключей
            self.public_key_text.delete(1.0, tk.END)
            self.public_key_text.insert(tk.END, f"e = {e}\n")
            self.public_key_text.insert(tk.END, f"n = {n}")

            self.private_key_text.delete(1.0, tk.END)
            self.private_key_text.insert(tk.END, f"d = {d}\n")
            self.private_key_text.insert(tk.END, f"n = {n}")

            self.file_info_text.delete(1.0, tk.END)
            self.file_info_text.insert(tk.END, "Ключи успешно сгенерированы!\n")
            self.file_info_text.insert(tk.END, f"Длина n: {n.bit_length()} бит\n")

            self.status_var.set("Ключи сгенерированы")

        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при генерации ключей: {str(e)}")

    def select_file(self):
        """Выбор файла для шифрования/дешифрования"""
        filename = filedialog.askopenfilename()
        if filename:
            self.current_file = filename
            file_size = os.path.getsize(filename)

            self.file_info_text.delete(1.0, tk.END)
            self.file_info_text.insert(tk.END, f"Выбран файл: {filename}\n")
            self.file_info_text.insert(tk.END, f"Размер: {file_size} байт\n")

            # Показ превью для текстовых файлов
            if file_size < 1024:  # Показываем превью только для маленьких файлов
                try:
                    with open(filename, 'r', encoding='utf-8') as f:
                        preview = f.read(200)
                        self.file_info_text.insert(tk.END, f"\nПревью:\n{preview}")
                        if file_size > 200:
                            self.file_info_text.insert(tk.END, "\n... (файл обрезан)")
                except:
                    try:
                        with open(filename, 'rb') as f:
                            preview = f.read(50)
                            hex_preview = ' '.join(f'{b:02x}' for b in preview)
                            self.file_info_text.insert(tk.END, f"\nПревью (hex):\n{hex_preview}")
                    except:
                        self.file_info_text.insert(tk.END, "\n(не удалось прочитать файл)")

            self.status_var.set(f"Выбран файл: {os.path.basename(filename)}")

    def rsa_encrypt(self, data):
        """Шифрование данных с использованием RSA"""
        if not self.public_key:
            raise ValueError("Открытый ключ не сгенерирован")

        e, n = self.public_key

        # Преобразование данных в числа и шифрование
        encrypted_blocks = []
        block_size = (n.bit_length() - 1) // 8  # Размер блока для шифрования

        for i in range(0, len(data), block_size):
            block = data[i:i + block_size]
            # Преобразование блока в число
            m = int.from_bytes(block, byteorder='big', signed=False)
            # Шифрование: c = m^e mod n
            if m >= n:
                # Если число слишком большое, разбиваем на меньшие блоки
                sub_block_size = block_size // 2
                for j in range(0, len(block), sub_block_size):
                    sub_block = block[j:j + sub_block_size]
                    m_sub = int.from_bytes(sub_block, byteorder='big', signed=False)
                    c_sub = pow(m_sub, e, n)
                    encrypted_blocks.append(c_sub.to_bytes((n.bit_length() + 7) // 8, byteorder='big'))
                continue

            c = pow(m, e, n)
            encrypted_blocks.append(c.to_bytes((n.bit_length() + 7) // 8, byteorder='big'))

        return b''.join(encrypted_blocks)

    def rsa_decrypt(self, data):
        """Дешифрование данных с использованием RSA"""
        if not self.private_key:
            raise ValueError("Закрытый ключ не сгенерирован")

        d, n = self.private_key
        block_size = (n.bit_length() + 7) // 8  # Размер зашифрованного блока

        decrypted_blocks = []

        for i in range(0, len(data), block_size):
            block = data[i:i + block_size]
            # Преобразование блока в число
            c = int.from_bytes(block, byteorder='big', signed=False)
            # Дешифрование: m = c^d mod n
            m = pow(c, d, n)
            # Определение размера исходного блока
            original_size = (m.bit_length() + 7) // 8
            decrypted_blocks.append(m.to_bytes(original_size, byteorder='big'))

        return b''.join(decrypted_blocks)

    def encrypt_file(self):
        """Шифрование файла"""
        if not self.current_file:
            messagebox.showwarning("Предупреждение", "Сначала выберите файл")
            return

        if not self.public_key:
            messagebox.showwarning("Предупреждение", "Сначала сгенерируйте ключи")
            return

        try:
            self.status_var.set("Шифрование...")
            self.progress_var.set(0)
            self.root.update()

            # Чтение файла
            with open(self.current_file, 'rb') as f:
                file_data = f.read()

            # Шифрование
            encrypted_data = self.rsa_encrypt(file_data)
            self.processed_data = encrypted_data

            # Показываем информацию о результате
            self.file_info_text.delete(1.0, tk.END)
            self.file_info_text.insert(tk.END, f"Файл зашифрован: {self.current_file}\n")
            self.file_info_text.insert(tk.END, f"Исходный размер: {len(file_data)} байт\n")
            self.file_info_text.insert(tk.END, f"Зашифрованный размер: {len(encrypted_data)} байт\n")

            # Показываем превью зашифрованных данных
            hex_preview = encrypted_data[:100].hex()
            self.file_info_text.insert(tk.END, f"\nПревью (hex):\n{hex_preview}")
            if len(encrypted_data) > 100:
                self.file_info_text.insert(tk.END, "\n... (данные обрезаны)")

            self.progress_var.set(100)
            self.status_var.set("Файл зашифрован")

        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при шифровании: {str(e)}")
            self.status_var.set("Ошибка шифрования")

    def decrypt_file(self):
        """Дешифрование файла"""
        if not self.current_file:
            messagebox.showwarning("Предупреждение", "Сначала выберите файл")
            return

        if not self.private_key:
            messagebox.showwarning("Предупреждение", "Сначала сгенерируйте ключи")
            return

        try:
            self.status_var.set("Дешифрование...")
            self.progress_var.set(0)
            self.root.update()

            # Чтение зашифрованного файла
            with open(self.current_file, 'rb') as f:
                encrypted_data = f.read()

            # Дешифрование
            decrypted_data = self.rsa_decrypt(encrypted_data)
            self.processed_data = decrypted_data

            # Показываем информацию о результате
            self.file_info_text.delete(1.0, tk.END)
            self.file_info_text.insert(tk.END, f"Файл расшифрован: {self.current_file}\n")
            self.file_info_text.insert(tk.END, f"Размер данных: {len(decrypted_data)} байт\n")

            # Попытка показать превью для текста
            try:
                text_preview = decrypted_data.decode('utf-8', errors='replace')[:200]
                self.file_info_text.insert(tk.END, f"\nПревью:\n{text_preview}")
                if len(decrypted_data) > 200:
                    self.file_info_text.insert(tk.END, "\n... (данные обрезаны)")
            except:
                hex_preview = decrypted_data[:100].hex()
                self.file_info_text.insert(tk.END, f"\nПревью (hex):\n{hex_preview}")
                if len(decrypted_data) > 100:
                    self.file_info_text.insert(tk.END, "\n... (данные обрезаны)")

            self.progress_var.set(100)
            self.status_var.set("Файл расшифрован")

        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при дешифровании: {str(e)}")
            self.status_var.set("Ошибка дешифрования")

    def save_result(self):
        """Сохранение результата шифрования/дешифрования"""
        if self.processed_data is None:
            messagebox.showwarning("Предупреждение", "Нет данных для сохранения")
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".bin",
            filetypes=[("All files", "*.*"), ("Text files", "*.txt"), ("Binary files", "*.bin")]
        )

        if filename:
            try:
                with open(filename, 'wb') as f:
                    f.write(self.processed_data)

                messagebox.showinfo("Успех", f"Данные сохранены в файл:\n{filename}")
                self.status_var.set(f"Данные сохранены: {os.path.basename(filename)}")

            except Exception as e:
                messagebox.showerror("Ошибка", f"Ошибка при сохранении: {str(e)}")
                self.status_var.set("Ошибка сохранения")


def main():
    root = tk.Tk()
    app = RSAApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()