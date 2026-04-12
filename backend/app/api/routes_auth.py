"""
Auth routes: login, token refresh, user management (admin), and /me.
"""
from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status

from app.core.security import (
    create_access_token,
    create_refresh_token,
    hash_password,
    verify_password,
    verify_token,
)
from app.database import crud
from app.database.schemas import (
    LoginRequest,
    RefreshTokenRequest,
    TokenResponse,
    UserCreate,
    UserRead,
)
from app.dependencies import get_current_user, get_db, require_admin

router = APIRouter()


@router.post("/login", response_model=TokenResponse)
async def login(payload: LoginRequest, db=Depends(get_db)):
    user = await crud.get_user_by_username(db, payload.username)
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account inactive")
    await crud.update_last_login(db, user.id)
    return TokenResponse(
        access_token=create_access_token(user.username, user.role),
        refresh_token=create_refresh_token(user.username),
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh(body: RefreshTokenRequest, db=Depends(get_db)):
    """Accept refresh_token in the request body (not query param) for security."""
    payload = verify_token(body.refresh_token)
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")
    username: str = payload.get("sub", "")
    user = await crud.get_user_by_username(db, username)
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return TokenResponse(
        access_token=create_access_token(user.username, user.role),
        refresh_token=create_refresh_token(user.username),
    )


@router.get("/me", response_model=UserRead)
async def get_me(current_user=Depends(get_current_user)):
    """Return the currently authenticated user's profile."""
    return current_user


@router.post("/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
async def register(
    payload: UserCreate,
    db=Depends(get_db),
    _admin=Depends(require_admin),
):
    existing = await crud.get_user_by_username(db, payload.username)
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already exists")
    user = await crud.create_user(db, payload.username, hash_password(payload.password), role=payload.role)
    return user


@router.get("/users", response_model=list[UserRead])
async def list_users(
    db=Depends(get_db),
    _admin=Depends(require_admin),
):
    """Admin-only: list all registered users."""
    users = await crud.list_users(db)
    return [UserRead.model_validate(u) for u in users]


@router.delete("/users/{username}", status_code=status.HTTP_204_NO_CONTENT)
async def deactivate_user(
    username: str,
    db=Depends(get_db),
    admin=Depends(require_admin),
):
    """Admin-only: soft-delete (deactivate) a user account."""
    if username == admin.username:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot deactivate yourself")
    user = await crud.deactivate_user(db, username)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
