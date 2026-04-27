# Кандидати для таблиці вразливостей HW02

## Мета

Підготувати 5 кандидатів, з яких у фінальний звіт буде відібрано щонайменше 4 найсильніші.

Це не фінальний звіт. Усі висновки нижче прив'язані до локальної лабораторії OWASP Juice Shop на `http://127.0.0.1:3000` і збережених HTTP-відповідей у `evidence/http/`.

## Таблиця за форматом домашнього завдання

| Ендпоінт | Метод | Токен? | Уразливість | STRIDE | CWE |
|---|---|---|---|---|---|
| `/api/Users` | GET | Так, JWT звичайного користувача | Broken Function Level Authorization | Elevation of Privilege | CWE-863 |
| `/rest/basket/{id}` | GET | Так, JWT користувача B | IDOR / BOLA | Information Disclosure | CWE-639 |
| `/rest/products/search?q='))--` | GET | Ні | SQL Injection | Tampering | CWE-89 |
| `/api/Users` | POST | Ні | Mass Assignment через `role: "admin"` | Elevation of Privilege | CWE-915 |
| `/api/Users` | GET | Так, JWT звичайного користувача | Excessive Data Exposure | Information Disclosure | CWE-200 |

## Кандидат 1 — Broken Function Level Authorization на `/api/Users`

### Дані для таблиці

- Ендпоінт: `/api/Users`
- Метод: GET
- Токен?: так, JWT звичайного користувача `customer`
- Уразливість: Broken Function Level Authorization
- STRIDE: Elevation of Privilege
- CWE: CWE-863 Incorrect Authorization
- Підтвердження: `evidence/http/02-api-users-no-token.txt`, `evidence/http/05-api-users-with-token.txt`, `evidence/screenshots/03-api-users-response.png`

### Що перевірялось

Перевірявся доступ до списку користувачів через `/api/Users`.

Команди:

```bash
BASE_URL="http://127.0.0.1:3000"
curl -sS -i "$BASE_URL/api/Users" | tee evidence/http/02-api-users-no-token.txt
curl -sS -i "$BASE_URL/api/Users" \
  -H "Authorization: Bearer <JWT звичайного користувача>" \
  | tee evidence/http/05-api-users-with-token.txt
```

### Що показав результат

Без токена endpoint повернув `401 Unauthorized`, тобто автентифікація потрібна. Але з JWT звичайного користувача endpoint повернув `200 OK` і JSON-список користувачів, включно з ролями `admin`, `customer`, `deluxe`.

### Чому це небезпечно

Звичайний користувач отримує доступ до функції, яка виглядає адміністративною: список акаунтів, ролі та службові поля. Це може допомогти в ескалації прав, зборі інформації про цілі та підготовці наступних атак.

### Реалістичні варіанти захисту

1. Додати централізовану RBAC/ABAC-перевірку для `/api/Users`, щоб доступ мали лише ролі з адміністративним scope.
2. Додати інтеграційні тести для ролей: звичайний користувач має отримувати `403 Forbidden`, адміністратор — дозволений результат.

### Статус для фінального звіту

- [x] залишити
- [ ] відкинути
- [ ] потребує додаткової перевірки

## Кандидат 2 — IDOR / BOLA при доступі до чужого кошика

### Дані для таблиці

- Ендпоінт: `/rest/basket/6`, `/rest/basket/7`
- Метод: GET
- Токен?: так, JWT користувача B
- Уразливість: IDOR / Broken Object Level Authorization
- STRIDE: Information Disclosure
- CWE: CWE-639 Authorization Bypass Through User-Controlled Key
- Підтвердження: `evidence/http/08-basket-7-with-token.txt`, `evidence/http/08b-basket-6-with-user-b-token.txt`, `evidence/screenshots/04-a-basket-access-check-6.png`, `evidence/screenshots/04-b-basket-access-check-7.png`

### Що перевірялось

Було створено двох локальних тестових користувачів. Після входу користувач A отримав `bid: 6`, користувач B отримав `bid: 7`. Спочатку користувач B з `TOKEN_B` відкрив власний basket ID 7 як контрольний запит, а потім тим самим `TOKEN_B` відкрив basket ID 6 іншого користувача.

Команди:

```bash
BASE_URL="http://127.0.0.1:3000"
curl -sS -i "$BASE_URL/rest/basket/7" \
  -H "Authorization: Bearer <JWT користувача B>" \
  | tee evidence/http/08-basket-7-with-token.txt
curl -sS -i "$BASE_URL/rest/basket/6" \
  -H "Authorization: Bearer <JWT користувача B>" \
  | tee evidence/http/08b-basket-6-with-user-b-token.txt
```

### Що показав результат

Контрольний запит користувача B до власного кошика `id: 7` повернув `200 OK`. Запит користувача B до чужого кошика `id: 6` з `UserId: 23` також повернув `200 OK`. Це показує, що API приймає ID ресурсу з URL і не блокує доступ до об'єкта іншого користувача.

### Чому це небезпечно

Якщо користувач може змінити ID у URL і читати чужий кошик, він може отримувати чужі дані або взаємодіяти з ресурсами, які йому не належать. Проблема виникає не через відсутність JWT, а через відсутність перевірки ownership між токеном і конкретним об'єктом.

### Реалістичні варіанти захисту

1. На рівні сервісу перевіряти, що `basket.UserId` збігається з `user_id` або `sub` з JWT; інакше повертати `403 Forbidden`.
2. Додати інтеграційні тести для доступу до власного й чужого basket ID, щоб IDOR не повертався після змін у коді.

### Статус для фінального звіту

- [x] залишити
- [ ] відкинути
- [ ] потребує додаткової перевірки

## Кандидат 3 — SQL Injection у пошуку товарів

### Дані для таблиці

- Ендпоінт: `/rest/products/search?q='))--`
- Метод: GET
- Токен?: ні
- Уразливість: SQL Injection
- STRIDE: Tampering
- CWE: CWE-89 SQL Injection
- Підтвердження: `evidence/http/01-products-search-apple.json`, `evidence/http/09-search-sqli-probe.txt`, `evidence/screenshots/02-api-get-apple.png`, `evidence/screenshots/05-sqli-search-response-deletedAt.png`

### Що перевірялось

Порівнювався нормальний пошук `q=apple` з ін'єкційним значенням `q='))--`.

Команди:

```bash
BASE_URL="http://127.0.0.1:3000"
curl -sS "$BASE_URL/rest/products/search?q=apple" \
  | tee evidence/http/01-products-search-apple.json
curl -sS -i --get "$BASE_URL/rest/products/search" \
  --data-urlencode "q='))--" \
  | tee evidence/http/09-search-sqli-probe.txt
```

### Що показав результат

Нормальний пошук `apple` повернув лише релевантні товари. Запит із `q='))--` повернув `200 OK` і великий список товарів, включно з позиціями, які не відповідають слову `apple`; у відповіді також є записи з `deletedAt`, тобто пошукова умова була обійдена або змінена.

### Чому це небезпечно

SQL Injection дозволяє впливати на логіку SQL-запиту через користувацький параметр. У реальній системі це може призвести до читання зайвих даних, обходу фільтрів, зміни даних або подальшої компрометації бази.

### Реалістичні варіанти захисту

1. Використовувати параметризовані SQL-запити або ORM binding замість конкатенації рядків із введенням користувача.
2. Додати валідацію та тест на ін'єкційні payload-и для параметра `q`, а також логування підозрілих пошукових запитів.

### Статус для фінального звіту

- [x] залишити
- [ ] відкинути
- [ ] потребує додаткової перевірки

## Кандидат 4 — Mass Assignment при реєстрації користувача

### Дані для таблиці

- Ендпоінт: `/api/Users`
- Метод: POST
- Токен?: ні
- Уразливість: Mass Assignment / присвоєння службового поля `role`
- STRIDE: Elevation of Privilege
- CWE: CWE-915 Improperly Controlled Modification of Dynamically-Determined Object Attributes
- Підтвердження: `evidence/http/10-post-users-mass-assignment-probe.txt`, `evidence/http/10b-post-users-role-admin-probe.txt`, `evidence/screenshots/06-mass-assignment-role-admin.png`

### Що перевірялось

Перевірялось, чи дозволяє endpoint реєстрації передати службові поля, які користувач не повинен контролювати. Варіант з `isAdmin: true` створив звичайного `customer`, але варіант з `role: "admin"` створив користувача з роллю `admin`.

Команди:

```bash
BASE_URL="http://127.0.0.1:3000"
curl -sS -i -X POST "$BASE_URL/api/Users" \
  -H "Content-Type: application/json" \
  --data '{"email":"hw02-role-20260427-1218@example.com","password":"Student123!","passwordRepeat":"Student123!","securityQuestion":{"id":1,"answer":"owl"},"role":"admin"}' \
  | tee evidence/http/10b-post-users-role-admin-probe.txt
```

### Що показав результат

Запит повернув `201 Created`, а в JSON-відповіді створений користувач має поле `"role":"admin"`. Це означає, що публічний endpoint приймає роль із тіла запиту замість того, щоб призначати її тільки на сервері.

### Чому це небезпечно

Користувач може самостійно встановити собі привілейовану роль під час реєстрації. У реальному застосунку це може дати адміністративні права без перевірки, тобто прямий шлях до ескалації привілеїв.

### Реалістичні варіанти захисту

1. Використовувати DTO/whitelist для реєстрації, де дозволені тільки `email`, `password`, `passwordRepeat` і `securityQuestion`, а `role` та `isAdmin` заборонені.
2. Призначати роль тільки на сервері за безпечним дефолтом, наприклад `customer`, і змінювати її лише через окремий адміністративний workflow з аудитом.

### Статус для фінального звіту

- [x] залишити
- [ ] відкинути
- [ ] потребує додаткової перевірки

## Кандидат 5 — Excessive Data Exposure у відповіді `/api/Users`

### Дані для таблиці

- Ендпоінт: `/api/Users`
- Метод: GET
- Токен?: так, JWT звичайного користувача
- Уразливість: Excessive Data Exposure / Broken Object Property Level Authorization
- STRIDE: Information Disclosure
- CWE: CWE-200 Exposure of Sensitive Information to an Unauthorized Actor
- Підтвердження: `evidence/http/05-api-users-with-token.txt`, `evidence/screenshots/03-api-users-response.png`

### Що перевірялось

Перевірялось не лише те, чи дозволений сам виклик `/api/Users`, а й які саме поля повертає відповідь звичайному користувачу.

Команда:

```bash
BASE_URL="http://127.0.0.1:3000"
curl -sS -i "$BASE_URL/api/Users" \
  -H "Authorization: Bearer <JWT звичайного користувача>" \
  | tee evidence/http/05-api-users-with-token.txt
```

### Що показав результат

Відповідь `200 OK` містить масив користувачів із такими полями, як `id`, `email`, `role`, `deluxeToken`, `lastLoginIp`, `profileImage`, `isActive`, `createdAt`, `updatedAt`. Частина цих полів не потрібна звичайному користувачу для нормальної роботи застосунку.

### Чому це небезпечно

Навіть якщо endpoint був би дозволений для частини сценаріїв, відповідь розкриває зайві дані про інших користувачів і ролі. Це спрощує розвідку, підбір цілей і комбінування з іншими вразливостями, наприклад IDOR або Broken Authorization.

### Реалістичні варіанти захисту

1. Використовувати response DTO/серіалізацію за роллю: звичайний користувач має бачити тільки мінімально потрібні поля і переважно лише власний профіль.
2. Додати property-level авторизацію та тести, які перевіряють, що службові поля (`role`, `deluxeToken`, внутрішні ID інших користувачів) не повертаються звичайному користувачу.

### Статус для фінального звіту

- [x] залишити
- [ ] відкинути
- [ ] потребує додаткової перевірки
