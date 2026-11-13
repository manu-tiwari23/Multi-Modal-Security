"""Authentication policy independent of FastAPI and other MMS modules."""

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import secrets
from threading import BoundedSemaphore

from src.shared.config import settings
from .models import AuthError, Principal, UserInput, username
from .passwords import hash_password, verify_password


def token_digest(token):
    return hashlib.sha256(token.encode()).hexdigest()


def csrf_token(token):
    return hmac.new(token.encode(), b"mms-session-csrf-v1", hashlib.sha256).hexdigest()


class AuthService:
    def __init__(self, repository, config=settings, clock=None):
        self.repository = repository
        self.config = config
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self._password_slots = BoundedSemaphore(2)
        self._dummy_hash = hash_password(secrets.token_urlsafe(32))

    def create_user(self, data: UserInput, actor):
        try:
            encoded = hash_password(data.password.get_secret_value())
        except ValueError as exc:
            raise AuthError(str(exc), 422) from exc
        self.repository.add_user({"username": data.username, "password_hash": encoded,
            "role": data.role, "disabled": False, "created_at": self.clock()}, actor)
        return {"username": data.username, "role": data.role, "disabled": False}

    def login(self, login_name, password, client_address):
        login_name = login_name.strip().lower()
        now = self.clock()
        for subject, limit in (("user:" + login_name, self.config.auth_login_attempts),
                               ("address:" + client_address, self.config.auth_login_attempts * 5)):
            if not self.repository.consume_attempt(token_digest(subject), now, self.config.auth_login_window_seconds, limit):
                raise AuthError("Too many sign-in attempts; try again later", 429)
        if not self._password_slots.acquire(blocking=False):
            raise AuthError("Sign-in is busy; try again shortly", 429)
        try:
            user = self.repository.get_user(login_name)
            valid = verify_password(password, user["password_hash"] if user else self._dummy_hash)
        finally:
            self._password_slots.release()
        if not valid or not user or user["disabled"]:
            self.repository.failed_login(login_name)
            raise AuthError("Invalid username or password")
        token = secrets.token_urlsafe(32)
        expiry = now + timedelta(seconds=self.config.auth_session_seconds)
        self.repository.create_session({"token_hash": token_digest(token), "username": user["username"],
            "expires_at": expiry, "last_seen": now, "revoked": False}, user["password_hash"])
        return token, Principal(username=user["username"], role=user["role"], expires_at=expiry,
                                session_hash=token_digest(token))

    def authenticate(self, token, touch=True):
        if not token or len(token) != 43 or not all(c.isalnum() or c in "_-" for c in token):
            raise AuthError("Sign in to continue")
        data = self.repository.resolve_session(token_digest(token), self.clock(), self.config.auth_idle_seconds, touch)
        if not data:
            raise AuthError("Session expired or revoked; sign in again")
        return Principal.model_validate(data)

    def logout(self, principal):
        self.repository.revoke_session(principal.session_hash, principal.username)

    def update_user(self, target, changes, actor):
        if not changes or set(changes) - {"role", "disabled"}:
            raise AuthError("Provide a role or enabled-state update", 422)
        try:
            target = username(target)
        except ValueError as exc:
            raise AuthError(str(exc), 422) from exc
        self.repository.change_user(target, changes, actor)

    def reset_password(self, target, password, actor):
        try:
            target = username(target)
            encoded = hash_password(password)
        except ValueError as exc:
            raise AuthError(str(exc), 422) from exc
        self.repository.change_user(target, {"password_hash": encoded}, actor)
