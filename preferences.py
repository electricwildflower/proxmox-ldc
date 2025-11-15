from __future__ import annotations

from typing import Any


def _get_account(root: Any) -> dict | None:
    app_state = getattr(root, "app_state", None)
    if isinstance(app_state, dict):
        account = app_state.get("account")
        if isinstance(account, dict):
            return account
    return None


def get_preferences(root: Any) -> dict:
    account = _get_account(root)
    if account is None:
        return {}
    prefs = account.setdefault("preferences", {})
    if not isinstance(prefs, dict):
        account["preferences"] = {}
        prefs = account["preferences"]
    return prefs


def get_preference(root: Any, key: str, default: str) -> str:
    prefs = get_preferences(root)
    value = prefs.get(key)
    if value is None:
        return default
    return value


def set_preference(root: Any, key: str, value: str) -> None:
    account = _get_account(root)
    if account is None:
        return
    prefs = account.setdefault("preferences", {})
    if prefs.get(key) == value:
        return
    prefs[key] = value
    store = getattr(root, "account_store", None)
    if store:
        store.save_account(account)

