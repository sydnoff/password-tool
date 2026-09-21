from lib import generate_salt, hash_password, check_password_strength, verify_password

TEST_PASSWORDS = ["qwerty", "Password1", "L!v1v2026#Poly"]


def demo_strength() -> None:
    """
    Виводить результати перевірки складності для кожного тестового пароля.

    Використовує функцію check_password_strength() з модуля lib.
    """
    print("=== Перевірка складності паролів ===")
    for password in TEST_PASSWORDS:
        result = check_password_strength(password)
        print(f"Пароль: {password}")
        print(f"  Оцінка: {result['score']}/{result['max_score']} ({result['level']})")
        if result["issues"]:
            print(f"  Зауваження: {', '.join(result['issues'])}")
        else:
            print("  Зауваження: відсутні")
    print()


def demo_hashing() -> None:
    """
    Демонструє повний цикл: генерація солі -> хешування -> перевірка пароля.

    Використовує функції generate_salt(), hash_password() та verify_password().
    """
    print("=== Хешування та перевірка пароля ===")
    password = TEST_PASSWORDS[-1]
    salt = generate_salt(8)
    stored_hash = hash_password(password, salt)

    print(f"Пароль:      {password}")
    print(f"Сіль:        {salt}")
    print(f"Хеш SHA-256: {stored_hash}")
    print(f"Перевірка правильного пароля: {verify_password(password, salt, stored_hash)}")
    print(f"Перевірка хибного пароля:     {verify_password('wrong', salt, stored_hash)}")
    print()

print ("hey")

def main() -> None:
    """
    Головна функція програми: послідовно запускає обидві демонстрації.
    """
    demo_strength()
    demo_hashing()
    print("Програму завершено успішно.")


# Код запускається лише при прямому виклику файлу, а не при його імпортуванні
if __name__ == "__main__":
    main()
