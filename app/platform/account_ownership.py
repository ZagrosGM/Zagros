"""One canonical core-account to user map, including temporary leases."""
from __future__ import annotations


def account_owners(runtime) -> dict[tuple[str, str], int]:
    owners = dict(runtime.users.account_owners())
    repository = getattr(runtime, "application_auth_repository", None)
    if repository is not None:
        owners.update(repository.lease_account_owners())
    return owners
