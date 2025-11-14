import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import os
import random
import math
import secrets


class ElGamalApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Асимметричная криптография - Эль-Гамаль (Вариант 4)")
        self.root.geometry("900x700")

        # Переменные для ключей
        self.public_key = None
        self.private_key = None
        self.p = None
        self.g = None
        self.x = None
        self.y = None

        # Переменные состояния
        self.current_file = None
        self.processed_data = None

        self.create_widgets()

    def create_widgets(self):
        """Создание элементов интерфейса"""
        # Заголовок
        title_label = tk.Label(self.root, text="Асимметричная криптография - Алгоритм Эль-Гамаля",
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

        tk.Label(param_frame, text="Битовая длина простого числа (минимум 32 бита):").grid(row=0, column=0, sticky='w',
                                                                                           pady=2)
        self.bit_length_var = tk.StringVar(value="32")
        bit_length_entry = tk.Entry(param_frame, textvariable=self.bit_length_var, width=10)
        bit_length_entry.grid(row=0, column=1, sticky='w', pady=2)

        # Кнопки генерации
        button_frame = tk.Frame(parent)
        button_frame.pack(fill='x', padx=10, pady=10)

        self.btn_generate_prime = tk.Button(button_frame, text="Сгенерировать простое число",
                                            command=self.generate_prime, padx=10, pady=5, bg="lightblue")
        self.btn_generate_prime.pack(side=tk.LEFT, padx=5)

        self.btn_generate_keys = tk.Button(button_frame, text="Сгенерировать ключи",
                                           command=self.generate_keys, padx=10, pady=5, bg="lightgreen")
        self.btn_generate_keys.pack(side=tk.LEFT, padx=5)

        # Область вывода ключей
        key_output_frame = tk.LabelFrame(parent, text="Сгенерированные ключи", padx=10, pady=10)
        key_output_frame.pack(fill='both', expand=True, padx=10, pady=5)

        # Простое число
        tk.Label(key_output_frame, text="Простое число p:").grid(row=0, column=0, sticky='w', pady=2)
        self.prime_text = scrolledtext.ScrolledText(key_output_frame, width=80, height=2)
        self.prime_text.grid(row=1, column=0, columnspan=2, sticky='nsew', pady=5)

        # Генератор
        tk.Label(key_output_frame, text="Генератор g:").grid(row=2, column=0, sticky='w', pady=2)
        self.generator_text = scrolledtext.ScrolledText(key_output_frame, width=80, height=1)
        self.generator_text.grid(row=3, column=0, columnspan=2, sticky='nsew', pady=5)

        # Открытый ключ
        tk.Label(key_output_frame, text="Открытый ключ (y, g, p):").grid(row=4, column=0, sticky='w', pady=2)
        self.public_key_text = scrolledtext.ScrolledText(key_output_frame, width=80, height=2)
        self.public_key_text.grid(row=5, column=0, columnspan=2, sticky='nsew', pady=5)

        # Закрытый ключ
        tk.Label(key_output_frame, text="Закрытый ключ (x):").grid(row=6, column=0, sticky='w', pady=2)
        self.private_key_text = scrolledtext.ScrolledText(key_output_frame, width=80, height=1)
        self.private_key_text.grid(row=7, column=0, columnspan=2, sticky='nsew', pady=5)

        key_output_frame.columnconfigure(0, weight=1)
        key_output_frame.rowconfigure(1, weight=1)
        key_output_frame.rowconfigure(3, weight=1)
        key_output_frame.rowconfigure(5, weight=1)
        key_output_frame.rowconfigure(7, weight=1)

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

    def lehman_test(self, n, tries=10):
        """Тест Лемана для проверки простоты числа (исправленная версия)"""
        if n < 2:
            return False
        if n == 2 or n == 3:
            return True
        if n % 2 == 0:
            return False

        for _ in range(tries):
            # Выбираем случайное число a, меньшее n
            a = random.randint(2, n - 2)

            # Вычисляем a^((n-1)/2) mod n
            exponent = (n - 1) // 2
            result = pow(a, exponent, n)

            # Если результат не равен 1 и не равен n-1, то число составное
            if result != 1 and result != n - 1:
                return False

        # Если все проверки пройдены, число вероятно простое
        return True

    def generate_prime_candidate(self, length):
        """Генерация кандидата в простые числа"""
        p = secrets.randbits(length)
        # Устанавливаем старший и младший биты в 1
        p |= (1 << (length - 1)) | 1
        return p

    def generate_prime_number(self, length=32):
        """Генерация простого числа с использованием теста Лемана"""
        self.status_var.set("Генерация простого числа...")
        self.root.update()

        max_attempts = 1000  # Ограничим количество попыток
        attempts = 0

        while attempts < max_attempts:
            p = self.generate_prime_candidate(length)
            attempts += 1

            # Быстрая проверка на маленькие простые делители для оптимизации
            small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]
            is_divisible = False
            for prime in small_primes:
                if p % prime == 0 and p != prime:
                    is_divisible = True
                    break

            if is_divisible:
                continue

            # Проверяем тестом Лемана
            if self.lehman_test(p, tries=20):
                return p

        raise ValueError(f"Не удалось найти простое число за {max_attempts} попыток")

    def generate_prime(self):
        """Генерация простого числа с использованием теста Лемана"""
        try:
            bit_length = int(self.bit_length_var.get())
            if bit_length < 32:
                messagebox.showwarning("Предупреждение", "Минимальная битовая длина - 32 бита")
                return

            self.p_value = self.generate_prime_number(bit_length)

            self.prime_text.delete(1.0, tk.END)
            self.prime_text.insert(tk.END, f"p = {self.p_value}\n")
            self.prime_text.insert(tk.END, f"Длина: {self.p_value.bit_length()} бит\n")
            self.prime_text.insert(tk.END, f"Проверка тестом Лемана: ПРОШЕЛ")

            self.status_var.set("Простое число сгенерировано")

        except ValueError as e:
            messagebox.showerror("Ошибка", str(e))
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при генерации простого числа: {str(e)}")

    def find_generator(self, p):
        """Поиск генератора для простого числа p"""
        if p == 2:
            return 1

        factors = []
        phi = p - 1
        n = phi

        # Факторизация phi = p-1
        i = 2
        while i * i <= n:
            if n % i == 0:
                factors.append(i)
                while n % i == 0:
                    n //= i
            i += 1
        if n > 1:
            factors.append(n)

        # Поиск генератора
        for g in range(2, p):
            if all(pow(g, phi // f, p) != 1 for f in factors):
                return g
        return None

    def generate_keys(self):
        """Генерация пары ключей Эль-Гамаля"""
        if not hasattr(self, 'p_value'):
            messagebox.showwarning("Предупреждение", "Сначала сгенерируйте простое число")
            return

        try:
            self.status_var.set("Генерация ключей...")
            self.root.update()

            p = self.p_value

            # Поиск генератора
            g = self.find_generator(p)
            if g is None:
                messagebox.showerror("Ошибка", "Не удалось найти генератор для данного простого числа")
                return

            # Выбор закрытого ключа x
            x = random.randint(2, p - 2)

            # Вычисление открытого ключа y
            y = pow(g, x, p)

            # Сохранение ключей
            self.public_key = (y, g, p)
            self.private_key = x
            self.p = p
            self.g = g
            self.x = x
            self.y = y

            # Вывод ключей
            self.generator_text.delete(1.0, tk.END)
            self.generator_text.insert(tk.END, f"g = {g}")

            self.public_key_text.delete(1.0, tk.END)
            self.public_key_text.insert(tk.END, f"y = {y}\n")
            self.public_key_text.insert(tk.END, f"g = {g}\n")
            self.public_key_text.insert(tk.END, f"p = {p}")

            self.private_key_text.delete(1.0, tk.END)
            self.private_key_text.insert(tk.END, f"x = {x}")

            self.file_info_text.delete(1.0, tk.END)
            self.file_info_text.insert(tk.END, "Ключи успешно сгенерированы!\n")
            self.file_info_text.insert(tk.END, f"Длина p: {p.bit_length()} бит\n")

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

    def elgamal_encrypt(self, data):
        """Шифрование данных с использованием Эль-Гамаля"""
        if not self.public_key:
            raise ValueError("Открытый ключ не сгенерирован")

        y, g, p = self.public_key

        # Преобразование данных в числа и шифрование
        encrypted_blocks = []

        for byte in data:
            m = byte

            # Выбор случайного k, взаимно простого с p-1
            k = random.randint(2, p - 2)
            while math.gcd(k, p - 1) != 1:
                k = random.randint(2, p - 2)

            # Вычисление a = g^k mod p
            a = pow(g, k, p)

            # Вычисление b = y^k * m mod p
            b = (pow(y, k, p) * m) % p

            encrypted_blocks.extend([a, b])

        return encrypted_blocks

    def elgamal_decrypt(self, data):
        """Дешифрование данных с использованием Эль-Гамаля"""
        if not self.private_key:
            raise ValueError("Закрытый ключ не сгенерирован")

        x = self.private_key
        p = self.p

        # Проверяем, что данные имеют правильную длину
        if len(data) % 2 != 0:
            raise ValueError("Некорректные данные для дешифрования")

        decrypted_blocks = []

        for i in range(0, len(data), 2):
            a = data[i]
            b = data[i + 1]

            # Вычисление s = a^x mod p
            s = pow(a, x, p)

            # Вычисление обратного элемента s_inv
            s_inv = pow(s, p - 2, p)  # По малой теореме Ферма

            # Вычисление m = b * s_inv mod p
            m = (b * s_inv) % p

            decrypted_blocks.append(m)

        return bytes(decrypted_blocks)

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
            encrypted_data = self.elgamal_encrypt(file_data)
            self.processed_data = bytes(encrypted_data)

            # Показываем информацию о результате
            self.file_info_text.delete(1.0, tk.END)
            self.file_info_text.insert(tk.END, f"Файл зашифрован: {self.current_file}\n")
            self.file_info_text.insert(tk.END, f"Исходный размер: {len(file_data)} байт\n")
            self.file_info_text.insert(tk.END, f"Зашифрованный размер: {len(self.processed_data)} байт\n")

            # Показываем превью зашифрованных данных
            hex_preview = self.processed_data[:100].hex()
            self.file_info_text.insert(tk.END, f"\nПревью (hex):\n{hex_preview}")
            if len(self.processed_data) > 100:
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
                encrypted_data = list(f.read())

            # Дешифрование
            decrypted_data = self.elgamal_decrypt(encrypted_data)
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
    app = ElGamalApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()