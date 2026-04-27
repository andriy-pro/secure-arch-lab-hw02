# Чекліст evidence для HW02

## Мета

Зібрати достатньо реальних доказів для звіту про REST API вразливості в локальному OWASP Juice Shop.

Домашнє завдання вимагає щонайменше 3 скриншоти. Наразі скриншотів достатньо для мінімальної вимоги, тому у фінальному звіті можна використовувати сильні докази без додавання слабкого filler.

## Наявні скриншоти

- [x] `evidence/screenshots/01-juice-shop-running.png` - Juice Shop запущений локально.
- [x] `evidence/screenshots/02-api-get-apple.png` - контрольний пошук `apple`.
- [x] `evidence/screenshots/03-api-users-response.png` - `/api/Users` з JWT звичайного користувача повертає `200 OK` і список користувачів.
- [x] `evidence/screenshots/04-a-basket-access-check-6.png` - користувач B з `TOKEN_B` отримує basket ID 6 іншого користувача.
- [x] `evidence/screenshots/04-b-basket-access-check-7.png` - користувач B з `TOKEN_B` отримує власний basket ID 7 як контрольний запит.
- [x] `evidence/screenshots/05-sqli-search-response-deletedAt.png` - SQLi probe `q='))--` повертає широкий список товарів, включно з записами `deletedAt`.
- [x] `evidence/screenshots/06-mass-assignment-role-admin.png` - `POST /api/Users` з `role: "admin"` повертає створеного користувача з роллю `admin`.

## Опційний скриншот

- [ ] `evidence/screenshots/07-jwt-decoded-redacted.png` - не створювався. Це опційний скриншот; для мінімальної вимоги він не потрібний, бо вже є більше ніж 3 релевантні скриншоти.

## Наявні HTTP-докази

- [x] `evidence/http/00-root-headers.txt` - заголовки відповіді головної сторінки, `200 OK`.
- [x] `evidence/http/01-products-search-apple.json` - контрольний пошук `apple`.
- [x] `evidence/http/02-api-users-no-token.txt` - `/api/Users` без токена повертає `401 Unauthorized`.
- [x] `evidence/http/03-register-user-a.json` - створення локального тестового користувача A.
- [x] `evidence/http/04-login-user-a.json` - логін користувача A, містить локальний JWT для лабораторії.
- [x] `evidence/http/05-api-users-with-token.txt` - `/api/Users` з JWT звичайного користувача повертає список користувачів.
- [x] `evidence/http/06-register-user-b.json` - створення локального тестового користувача B.
- [x] `evidence/http/07-login-user-b.json` - логін користувача B, містить локальний JWT для лабораторії.
- [x] `evidence/http/08-basket-7-with-token.txt` - контрольний доступ користувача B до власного basket ID 7.
- [x] `evidence/http/08b-basket-6-with-user-b-token.txt` - користувач B отримує basket ID 6 іншого користувача.
- [x] `evidence/http/08c-basket-7-with-user-a-token.txt` - користувач A отримує basket ID 7 іншого користувача.
- [x] `evidence/http/09-search-sqli-probe.txt` - SQLi probe `q='))--` повертає широкий список товарів.
- [x] `evidence/http/10-post-users-mass-assignment-probe.txt` - `isAdmin: true` не підтвердив ескалацію, створено `customer`.
- [x] `evidence/http/10b-post-users-role-admin-probe.txt` - `role: "admin"` створив користувача з роллю `admin`.

## Нотатки з безпеки перед фіналізацією

- Скриншотів достатньо для вимоги "щонайменше 3 скриншоти"; у звіті варто посилатися на всі ключові докази.
- Повні значення JWT у звіті не наводяться; у тексті та посиланнях на підтвердження використовуються плейсхолдери або редаговані значення.
- Повні JWT не можна вставляти у `report.md`, нотатки або Google Doc. Якщо треба згадати токен, достатньо написати: "JWT звичайного користувача, повне значення не наводиться".
- Файли логіну в `evidence/http/` містять локальні JWT з лабораторії. Перед commit або пакуванням треба виконати hygiene check і переконатися, що такі значення не потрапили у звіт.
