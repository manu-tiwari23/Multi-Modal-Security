"""Cookie sessions, CSRF and authorization at the API boundary."""

import hmac
import re

from fastapi import APIRouter, Depends, HTTPException, Request, Response, WebSocketException
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from starlette.requests import HTTPConnection

from src.auth.models import AuthError, AuthStoreUnavailable, Principal, Role, UserInput
from src.auth.runtime import get_auth_service
from src.auth.service import csrf_token
from src.shared.config import settings

COOKIE_NAME = "mms_session"
PUBLIC_ROUTES = {"/api/auth/login", "/api/auth/status", "/api/health"}


def reject(connection, status, detail):
    if connection.scope["type"] == "websocket":
        raise WebSocketException(code=1008, reason=detail)
    raise HTTPException(status, detail)


def check_origin(connection, required=False):
    origin = connection.headers.get("origin")
    if (required and not origin) or (origin and origin not in settings.auth_allowed_origins):
        reject(connection, 403, "Request origin is not allowed")


def get_principal(connection: HTTPConnection):
    token = connection.cookies.get(COOKIE_NAME, "")
    if not token:
        reject(connection, 401, "Sign in to continue")
    try:
        principal = get_auth_service().authenticate(token)
    except AuthError as exc:
        reject(connection, exc.status, str(exc))
    except AuthStoreUnavailable:
        reject(connection, 503, "Authentication storage unavailable; retry later")
    connection.state.principal = principal
    return principal


def authorize_request(connection: HTTPConnection):
    method = connection.scope.get("method", "GET")
    check_origin(connection, required=connection.scope["type"] == "websocket")
    if connection.url.path in PUBLIC_ROUTES:
        return None
    principal = get_principal(connection)
    if method not in ("GET", "HEAD", "OPTIONS"):
        token = connection.cookies.get(COOKIE_NAME, "")
        supplied = connection.headers.get("x-mms-csrf", "")
        if not re.fullmatch(r"[0-9a-f]{64}", supplied) or not hmac.compare_digest(supplied, csrf_token(token)):
            reject(connection, 403, "Session verification failed; refresh and try again")
        if principal.role == "viewer" and connection.url.path not in ("/api/auth/logout", "/api/auth/password"):
            reject(connection, 403, "An analyst role is required for this action")
    return principal


def require_analyst(principal: Principal = Depends(authorize_request)):
    if principal is None or principal.role not in ("analyst", "admin"):
        raise HTTPException(403, "An analyst role is required")
    return principal


def require_admin(principal: Principal = Depends(authorize_request)):
    if principal is None or principal.role != "admin":
        raise HTTPException(403, "An administrator role is required")
    return principal


def bind_actor(claimed, principal):
    if claimed is not None and claimed.strip().lower() != principal.username:
        raise HTTPException(403, "Actor must match the signed-in analyst")
    return principal.username


class LoginBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=1, max_length=64)
    password: SecretStr = Field(min_length=1, max_length=128)


class AccountUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: Role | None = None
    disabled: bool | None = None


class PasswordBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    password: SecretStr = Field(min_length=15, max_length=128)


class OwnPasswordBody(PasswordBody):
    current_password: SecretStr = Field(min_length=1, max_length=128)


router = APIRouter(prefix="/api/auth", tags=["Authentication"])


def session_response(principal, token):
    return {"user": principal.model_dump(), "csrf_token": csrf_token(token)}


@router.get("/status")
def auth_status():
    return {"setup_required": not bool(get_auth_service().repository.list_users())}


@router.post("/login")
def login(body: LoginBody, request: Request, response: Response):
    if request.headers.get("content-type", "").split(";")[0] != "application/json":
        raise HTTPException(415, "JSON sign-in request required")
    check_origin(request)
    token, principal = get_auth_service().login(body.username, body.password.get_secret_value(),
        request.client.host if request.client else "unknown")
    response.set_cookie(COOKIE_NAME, token, httponly=True, secure=settings.auth_cookie_secure,
                        samesite="strict", path="/", max_age=settings.auth_session_seconds)
    response.headers["Cache-Control"] = "no-store"
    return session_response(principal, token)


@router.get("/session")
def current_session(request: Request, response: Response, principal: Principal = Depends(authorize_request)):
    response.headers["Cache-Control"] = "no-store"
    return session_response(principal, request.cookies[COOKIE_NAME])


@router.post("/logout", status_code=204)
def logout(response: Response, principal: Principal = Depends(authorize_request)):
    get_auth_service().logout(principal)
    response.delete_cookie(COOKIE_NAME, path="/", httponly=True, secure=settings.auth_cookie_secure, samesite="strict")


@router.get("/users")
def list_users(principal: Principal = Depends(require_admin)):
    return {"users": get_auth_service().repository.list_users()}


@router.post("/users", status_code=201)
def create_user(body: UserInput, principal: Principal = Depends(require_admin)):
    return get_auth_service().create_user(body, principal.username)


@router.patch("/users/{username}", status_code=204)
def update_user(username: str, body: AccountUpdate, principal: Principal = Depends(require_admin)):
    get_auth_service().update_user(username, body.model_dump(exclude_none=True), principal.username)


@router.post("/users/{username}/password", status_code=204)
def reset_password(username: str, body: PasswordBody, principal: Principal = Depends(require_admin)):
    get_auth_service().reset_password(username, body.password.get_secret_value(), principal.username)


@router.post("/password", status_code=204)
def change_own_password(body: OwnPasswordBody, response: Response, principal: Principal = Depends(authorize_request)):
    from src.auth.passwords import verify_password
    service = get_auth_service()
    user = service.repository.get_user(principal.username)
    if not user or not verify_password(body.current_password.get_secret_value(), user["password_hash"]):
        raise HTTPException(403, "Current password is incorrect")
    service.reset_password(principal.username, body.password.get_secret_value(), principal.username)
    response.delete_cookie(COOKIE_NAME, path="/")
