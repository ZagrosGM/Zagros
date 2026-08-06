from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy.orm import Session

from app import logger, scheduler, xray
from app.db import (GetDB, get_notification_reminder, get_users,
                    start_user_expire, update_user_status, reset_user_by_next)
from app.models.user import ReminderType, UserResponse, UserStatus
from app.utils import report
from app.utils.helpers import (calculate_expiration_days,
                               calculate_usage_percent)
from config import (JOB_REVIEW_USERS_INTERVAL, NOTIFY_DAYS_LEFT,
                    NOTIFY_REACHED_USAGE_PERCENT, WEBHOOK_ADDRESS)

if TYPE_CHECKING:
    from app.db.models import User


def _bridge_platform_status(user: "User") -> None:
    """Status changes inside jobs (expiry/limit/on-hold) must converge onto the
    platform projection too — otherwise a core account keeps working after the
    legacy user dies. Best-effort: a broken bridge never blocks the review."""
    try:
        import app as _app

        runtime = getattr(_app.app.state, "zagros", None)
    except Exception:  # noqa: BLE001 — never crash the review job
        return
    if runtime is None:
        return
    try:
        import asyncio

        from app.platform import provisioning

        asyncio.run(provisioning.sync_user(runtime, user, None))
    except Exception as exc:  # noqa: BLE001
        logger.warning(f"platform status sync failed for {user.username}: {exc}")


def add_notification_reminders(db: Session, user: "User", now: datetime = datetime.utcnow()) -> None:
    if user.data_limit:
        usage_percent = calculate_usage_percent(user.used_traffic, user.data_limit)

        for percent in sorted(NOTIFY_REACHED_USAGE_PERCENT, reverse=True):
            if usage_percent >= percent:
                if not get_notification_reminder(db, user.id, ReminderType.data_usage, threshold=percent):
                    report.data_usage_percent_reached(
                        db, usage_percent, UserResponse.model_validate(user),
                        user.id, user.expire, threshold=percent
                    )
                break

    if user.expire:
        expire_days = calculate_expiration_days(user.expire)

        for days_left in sorted(NOTIFY_DAYS_LEFT):
            if expire_days <= days_left:
                if not get_notification_reminder(db, user.id, ReminderType.expiration_date, threshold=days_left):
                    report.expire_days_reached(
                        db, expire_days, UserResponse.model_validate(user),
                        user.id, user.expire, threshold=days_left
                    )
                break


def reset_user_by_next_report(db: Session, user: "User"):
    user = reset_user_by_next(db, user)

    xray.operations.update_user(user)

    report.user_data_reset_by_next(user=UserResponse.model_validate(user), user_admin=user.admin)


def review_admin_consumption(db: Session) -> None:
    """Alpha.7 governance: enforce every admin's traffic-consumption cap.

    Over the cap -> the admin's active users are suspended (flagged);
    back under (cap raised/removed) -> exactly those users revive.
    Core sync happens once at the end if anything changed.
    """
    from app.db.models import Admin

    needs_core_sync = False
    admins = db.query(Admin).all()
    from app.db import crud
    for dbadmin in admins:
        if dbadmin.traffic_consume_limit is None:
            # no cap: only repair dangling flags from a removed cap
            if not any(u.admin_limit_disabled for u in (dbadmin.users or [])):
                continue
        changed = crud.enforce_admin_consumption(db, dbadmin)
        needs_core_sync = needs_core_sync or bool(
            changed["suspended"] or changed["reactivated"])
        for username in [u.username for u in changed["suspended"]]:
            logger.info(f'User "{username}" suspended — admin '
                        f'"{dbadmin.username}" crossed the consumption cap')
        for username in [u.username for u in changed["reactivated"]]:
            logger.info(f'User "{username}" re-activated — admin '
                        f'"{dbadmin.username}" is back under the consumption cap')
    if needs_core_sync:
        startup_config = xray.config.include_db_users()
        xray.core.restart(startup_config)


def review():
    now = datetime.utcnow()
    now_ts = now.timestamp()
    with GetDB() as db:
        try:
            review_admin_consumption(db)
        except Exception as exc:  # noqa: BLE001 — never kill the review loop
            logger.error(f"admin consumption review failed: {exc}")
        for user in get_users(db, status=UserStatus.active):

            limited = user.data_limit and user.used_traffic >= user.data_limit
            expired = user.expire and user.expire <= now_ts

            if (limited or expired) and user.next_plan is not None:
                if user.next_plan is not None:

                    if user.next_plan.fire_on_either:
                        reset_user_by_next_report(db, user)
                        continue

                    elif limited and expired:
                        reset_user_by_next_report(db, user)
                        continue

            if limited:
                status = UserStatus.limited
            elif expired:
                status = UserStatus.expired
            else:
                if WEBHOOK_ADDRESS:
                    add_notification_reminders(db, user, now)
                continue

            xray.operations.remove_user(user)
            update_user_status(db, user, status)

            report.status_change(username=user.username, status=status,
                                 user=UserResponse.model_validate(user), user_admin=user.admin)
            _bridge_platform_status(user)

            logger.info(f"User \"{user.username}\" status changed to {status}")

        for user in get_users(db, status=UserStatus.on_hold):

            if user.edit_at:
                base_time = datetime.timestamp(user.edit_at)
            else:
                base_time = datetime.timestamp(user.created_at)

            # Check if the user is online After or at 'base_time'
            if user.online_at and base_time <= datetime.timestamp(user.online_at):
                status = UserStatus.active

            elif user.on_hold_timeout and (datetime.timestamp(user.on_hold_timeout) <= (now_ts)):
                # If the user didn't connect within the timeout period, change status to "Active"
                status = UserStatus.active

            else:
                continue

            update_user_status(db, user, status)
            start_user_expire(db, user)

            report.status_change(username=user.username, status=status,
                                 user=UserResponse.model_validate(user), user_admin=user.admin)
            _bridge_platform_status(user)

            logger.info(f"User \"{user.username}\" status changed to {status}")


scheduler.add_job(review, 'interval',
                  seconds=JOB_REVIEW_USERS_INTERVAL,
                  coalesce=True, max_instances=1)
