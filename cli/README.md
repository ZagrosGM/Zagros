# zagros-cli

`zagros-cli` is the built-in administration CLI shipped inside the Zagros
panel (entry point: `zagros-cli.py`, installed into the container image as
`zagros-cli`). It talks directly to the panel database and needs the same
environment (`.env` / `SQLALCHEMY_DATABASE_URL`) as the running panel.

> Looking for the server management CLI (install / update / backup /
> doctor / cores)? That is the standalone `zagros` tool, maintained in the
> [zagros-scripts](https://github.com/ZagrosGM/zagros-scripts) repository.

## Usage

```bash
zagros-cli --help
zagros-cli admin --help
zagros-cli user --help
zagros-cli subscription --help
```

## Admin commands

| Command | Description |
|---|---|
| `zagros-cli admin list` | List admins (optionally filtered). |
| `zagros-cli admin create` | Create an admin interactively (`--sudo` for full access, `--telegram-id`, `--discord-webhook`). |
| `zagros-cli admin update <username>` | Update an admin's password / flags interactively. |
| `zagros-cli admin delete <username>` | Delete an admin (`--yes` to skip confirmation). |
| `zagros-cli admin import-from-env` | Create/update the sudo admin from `SUDO_USERNAME` / `SUDO_PASSWORD` environment variables. |

Passwords can also be supplied non-interactively via the
`ZAGROS_ADMIN_PASSWORD` environment variable where a password prompt would
otherwise appear.

## User commands

| Command | Description |
|---|---|
| `zagros-cli user list` | List users (filterable), with quota/status columns. |
| `zagros-cli user set-owner <username> --admin <admin>` | Re-assign a user to a different admin. |

## Subscription commands

| Command | Description |
|---|---|
| `zagros-cli subscription get-link <username>` | Print the user's subscription link. Needs `XRAY_SUBSCRIPTION_URL_PREFIX`. |
| `zagros-cli subscription get-config <username>` | Print the user's subscription config payload to stdout. |

## Shell completion

```bash
zagros-cli completion install --shell bash
```

## Development

The code lives in `cli/` (Typer). When adding a command, update this README
in the same commit.
