"""
lib.py — допоміжний модуль лабораторної роботи № 1.

Містить набір функцій для базової перевірки та захисту паролів.
Модуль не виконує жодних дій при імпортуванні — лише оголошує функції,
які використовує main.py.
"""

import hashlib
import secrets
import string

# Мінімальна допустима довжина пароля (використовується у check_password_strength)
MIN_LENGTH = 8


def generate_salt(length: int = 16) -> str:
    """
    Генерує криптографічно стійку "сіль" для хешування пароля.

    :param length: кількість байтів випадкових даних (за замовчуванням 16)
    :return: сіль у вигляді шістнадцяткового рядка
    """
    return secrets.token_hex(length)


def hash_password(password: str, salt: str) -> str:
    """
    Обчислює SHA-256 хеш пароля разом із сіллю.

    Сіль додається до пароля перед хешуванням, щоб однакові паролі
    різних користувачів мали різні хеші (захист від rainbow-таблиць).

    :param password: вихідний пароль у відкритому вигляді
    :param salt: сіль, отримана з generate_salt()
    :return: хеш у вигляді шістнадцяткового рядка (64 символи)
    """
    data = (salt + password).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def check_password_strength(password: str) -> dict:
    """
    Оцінює складність пароля за чотирма критеріями.

    Критерії: довжина, наявність великих літер, цифр та спеціальних символів.
    За кожен виконаний критерій нараховується 1 бал (максимум 4).

    :param password: пароль для перевірки
    :return: словник з ключами 'score', 'max_score', 'level', 'issues'
    """
    issues = []
    score = 0

    if len(password) >= MIN_LENGTH:
        score += 1
    else:
        issues.append(f"довжина менша за {MIN_LENGTH} символів")

    if any(c.isupper() for c in password):
        score += 1
    else:
        issues.append("немає великих літер")

    if any(c.isdigit() for c in password):
        score += 1
    else:
        issues.append("немає цифр")

    if any(c in string.punctuation for c in password):
        score += 1
    else:
        issues.append("немає спеціальних символів")

    return {
        "score": score,
        "max_score": 4,
        "level": _score_to_level(score),
        "issues": issues,
    }


def _score_to_level(score: int) -> str:
    """
    Перетворює числову оцінку складності у текстову характеристику.

    Внутрішня (приватна) функція — на це вказує префікс "_" в імені.

    :param score: кількість набраних балів (0..4)
    :return: текстовий рівень складності пароля
    """
    levels = {0: "дуже слабкий", 1: "слабкий", 2: "середній", 3: "хороший", 4: "надійний"}
    return levels.get(score, "невідомий")


def verify_password(password: str, salt: str, expected_hash: str) -> bool:
    """
    Перевіряє, чи відповідає введений пароль збереженому хешу.

    Порівняння виконується функцією secrets.compare_digest, стійкою до
    атак за часом виконання (timing attack).

    :param password: пароль, введений користувачем
    :param salt: сіль, збережена разом із хешем
    :param expected_hash: еталонний хеш із "бази даних"
    :return: True, якщо пароль правильний, інакше False
    """
    return secrets.compare_digest(hash_password(password, salt), expected_hash)
