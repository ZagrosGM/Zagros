# Zagros

**Корпоративная мультиядерная платформа управления VPN** — подключаемые ядра,
единая квота, единые устройства, защищённая (sealed) доставка клиентам.

Каждая VPN-технология в Zagros — **первоклассный плагин**; Xray не имеет
особого статуса и является лишь одним из драйверов.

> **Происхождение:** Zagros — глубокая переработка форка панели
> [Marzban](https://github.com/Gozargah/Marzban) (AGPL-3.0) в полностью
> плагинную мультиядерную платформу. Авторские права и лицензия AGPL-3.0
> сохранены (`LICENSE`); встроен и протестирован путь миграции с Marzban v0.8.x.

## Ключевые возможности

* **8 встроенных драйверов ядер** — xray, sing-box, WireGuard, OpenVPN,
  Hysteria 2, TUIC v5, SSH, SoftEther — за одним контрактом.
* **Единая квота** — один счётчик на пользователя по всем ядрам с
  персистентными базовыми линиями (учёт ровно один раз).
* **Единые менеджеры устройств и сессий.**
* **Центральные движки Routing / Outbound / Policy** с честными отчётами.
* **Кросс-ядровые цепочки** (cross-core chaining).
* **Динамический портал подписок** + бэкенд официального приложения
  (sealed delivery: X25519 + HKDF-SHA256 + AES-256-GCM).
* **Config Studio** — графическое управление конфигурацией + Advanced Mode.
* **SQLAlchemy + Alembic**, шифрование учётных данных (AES-256-GCM),
  идемпотентная миграция с dry-run и откатом.

## Разработка

```bash
pip install -r requirements.txt
python -m pytest tests/
alembic upgrade head
python main.py
```

Документация: `docs/MULTICORE-ARCHITECTURE.md`

## Сообщество

* **Telegram-канал (анонсы):** <https://t.me/zagrosgm>
* **Telegram-группа (обсуждение и поддержка):** <https://t.me/zagrosgm_group>
* **Репозиторий GitHub:** <https://github.com/ZagrosGM/Zagros>
* **Установщик и CLI:** <https://github.com/ZagrosGM/zagros-scripts>

Как помочь проекту: см. `CONTRIBUTING.md` в основном репозитории.

## Лицензия

AGPL-3.0 — с полным сохранением прав авторов Marzban.
