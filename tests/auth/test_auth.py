from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from src.auth.models import AuthError, UserInput
from src.auth.passwords import hash_password, verify_password
from src.auth.repository import MemoryAuthRepository
from src.auth.service import AuthService, token_digest

PASSWORD = "Synthetic login passphrase 2026!"


@pytest.fixture
def service():
    config = SimpleNamespace(auth_session_seconds=600, auth_idle_seconds=60,
                             auth_login_attempts=3, auth_login_window_seconds=30)
    return AuthService(MemoryAuthRepository(), config)


def create(service, name="alice", role="analyst"):
    service.create_user(UserInput(username=name, password=PASSWORD, role=role), "local_operator")


def test_password_hash_is_salted_and_wrong_password_fails():
    first, second = hash_password(PASSWORD), hash_password(PASSWORD)
    assert first != second and PASSWORD not in first
    assert verify_password(PASSWORD, first)
    assert not verify_password("incorrect password", first)
    assert not verify_password(PASSWORD, "malformed")
    with pytest.raises(ValueError):
        hash_password("short")


def test_opaque_tokens_are_stored_only_as_hashes_and_logout_revokes(service):
    create(service)
    token, principal = service.login("ALICE", PASSWORD, "test-client")
    assert token not in str(service.repository.sessions)
    assert token_digest(token) in service.repository.sessions
    assert service.authenticate(token).username == "alice"
    service.logout(principal)
    with pytest.raises(AuthError):
        service.authenticate(token)


def test_idle_and_absolute_expiry_are_checked_server_side(service):
    create(service)
    now = datetime.now(timezone.utc)
    service.clock = lambda: now
    token, _ = service.login("alice", PASSWORD, "client")
    service.clock = lambda: now + timedelta(seconds=61)
    with pytest.raises(AuthError):
        service.authenticate(token)
    service.clock = lambda: now
    token, _ = service.login("alice", PASSWORD, "client")
    for seconds in range(50, 601, 50):
        service.clock = lambda: now + timedelta(seconds=seconds)
        if seconds < 600:
            assert service.authenticate(token).username == "alice"
        else:
            with pytest.raises(AuthError):
                service.authenticate(token)


def test_password_or_role_change_revokes_sessions(service):
    create(service)
    token, _ = service.login("alice", PASSWORD, "client")
    service.update_user("alice", {"role": "viewer"}, "admin")
    with pytest.raises(AuthError):
        service.authenticate(token)
    token, _ = service.login("alice", PASSWORD, "client")
    service.reset_password("alice", "New synthetic passphrase 2026!", "admin")
    with pytest.raises(AuthError):
        service.authenticate(token)


def test_failed_login_throttle_is_shared_by_services(service):
    create(service)
    for _ in range(3):
        with pytest.raises(AuthError) as error:
            service.login("alice", "incorrect password", "client")
        assert error.value.status == 401
    other = AuthService(service.repository, service.config)
    with pytest.raises(AuthError) as error:
        other.login("alice", PASSWORD, "another-client")
    assert error.value.status == 429


def test_last_enabled_admin_cannot_be_disabled_or_demoted(service):
    create(service, "admin", "admin")
    for changes in ({"disabled": True}, {"role": "viewer"}):
        with pytest.raises(AuthError) as error:
            service.update_user("admin", changes, "admin")
        assert error.value.status == 409
    create(service, "second-admin", "admin")
    service.update_user("admin", {"disabled": True}, "second-admin")
    with pytest.raises(AuthError):
        service.login("admin", PASSWORD, "client")


def test_automated_identity_cannot_be_created(service):
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        UserInput(username="copilot", password=PASSWORD)
