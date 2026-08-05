# Zagros

**企业级多内核 VPN 管理平台** — 可插拔内核、统一配额、统一设备、密封客户端交付。

在 Zagros 中，每种 VPN 技术都是**一等插件**；Xray 没有任何特殊地位，
只是众多驱动之一。

> **渊源:** Zagros 是对 [Marzban](https://github.com/Gozargah/Marzban) 面板
> (AGPL-3.0) 的深度重构，将其打造成完全插件化的多内核平台。上游版权与
> AGPL-3.0 协议完整保留（见 `LICENSE`），并内置且测试了从 Marzban v0.8.x
> 的迁移路径。

## 核心特性

* **8 个内置内核驱动** — xray、sing-box、WireGuard、OpenVPN、Hysteria 2、
  TUIC v5、SSH、SoftEther — 统一契约。
* **统一配额** — 每用户一个计数器，跨全部内核；持久化基线（重启后精确一次计量）。
* **统一设备与会话管理** — 全局设备限制与会话历史。
* **集中式 Routing / Outbound / Policy 引擎** — 如实报告每个内核的能力差距。
* **跨内核链式路由**。
* **动态订阅门户** — 两种交付模式：订阅链接 / 应用登录；官方 App 后端，
  配置仅经密封通道下发（X25519 + HKDF-SHA256 + AES-256-GCM）。
* **Config Studio** — 图形化配置管理 + Advanced 模式（原始 JSON + Diff）。
* **现代持久层** — SQLAlchemy + Alembic，凭据静态加密（AES-256-GCM），
  幂等迁移（支持 dry-run 与回滚）。

## 开发

```bash
pip install -r requirements.txt
python -m pytest tests/
alembic upgrade head
python main.py
```

文档：`docs/MULTICORE-ARCHITECTURE.md`

## 许可证

AGPL-3.0 — 完整保留 Marzban 原作者的版权。
