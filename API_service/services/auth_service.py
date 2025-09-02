from datetime import datetime, timedelta, timezone
from typing import Optional, Any, Coroutine

from ..config import settings
from ..core.db_helper import db_helper
from ..core.model import RefreshToken, User
from ..core.schemas import UserCreate
from fastapi import Depends, HTTPException, status
from jose import jwt, JWTError
from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class AuthService:
    """
    Сервис для обработки операций аутентификации.
    Включает хеширование паролей, верификацию, создание JWT-токенов,
    регистрацию и аутентификацию пользователей.
    """

    @staticmethod
    def get_password_hash(password: str) -> str:
        """
        Генерация безопасного хеша для пароля.
        :param password: Пароль в открытом виде
        :return: str: Хешированный пароль
        """
        return pwd_context.hash(password)

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """
        Проверка пароля.
        :param plain_password: Пароль для проверки
        :param hashed_password: Хранимый хеш пароля
        :return:  bool: True если пароли совпадают, иначе False
        """
        return pwd_context.verify(plain_password, hashed_password)

    @staticmethod
    def create_access_token(data: dict, expires_delta: timedelta = None) -> str:
        """
        Создание JWT-токена доступа.
        :param data: Данные для включения в токен
        :param expires_delta:
        :return: str: Закодированный JWT-токен
        """
        to_encode = data.copy()
        expire = datetime.now(tz=timezone.utc) + (
            expires_delta or timedelta(minutes=settings.auth.ACCESS_EXPIRE_MINUTES)
        )
        to_encode.update({"exp": int(expire.timestamp())})
        return jwt.encode(
            to_encode,
            settings.auth.secret_key,
            algorithm=settings.auth.algorithm,
        )

    @staticmethod
    def create_refresh_token(user_id: int) -> str:
        """Создает обновленный JWT-токен"""

        expires = timedelta(days=settings.auth.REFRESH_EXPIRE_DAYS)
        return jwt.encode(
            {"sub": str(user_id), "type": "refresh"},
            settings.auth.secret_key,
            algorithm=settings.auth.algorithm,
        )

    @classmethod
    async def persist_refresh_token(
            cls,
            user_id: int,
            refresh_token: str,
            session: AsyncSession
    ):
        # Отзываем старые токены
        stmt = select(RefreshToken).where(
            RefreshToken.user_id == user_id,
            RefreshToken.revoked == False,
        )
        result = await session.execute(stmt)
        for token in result.scalars().all():
            token.revoked = True

        # Сохраняем новый токен
        hashed = pwd_context.hash(refresh_token)
        new_token = RefreshToken(
            user_id=user_id,
            token_hash=hashed,
            expires_at=datetime.now(timezone.utc) + timedelta(days=settings.auth.REFRESH_EXPIRE_DAYS),
            revoked=False,
        )
        session.add(new_token)
        await session.commit()

    @classmethod
    async def register(
            cls,
            user_data: UserCreate,
            session: AsyncSession = Depends(db_helper.session_getter),
    ) -> User:
        """
        Регистрация нового пользователя.
        """
        if not user_data.email or not user_data.password:
            raise HTTPException(status_code=400, detail="Email и пароль обязательны")

        # Упрощенная проверка существования пользователя
        existing_user = await session.execute(
            select(User).where(User.email == user_data.email)
        )
        if existing_user.scalar_one_or_none():
            raise HTTPException(
                status_code=400,
                detail="Пользователь с таким email уже существует"
            )

        user = User(
            email=user_data.email,
            pass_hash=cls.get_password_hash(user_data.password),
            is_active=True,
        )

        session.add(user)
        try:
            await session.commit()
            await session.refresh(user)
            return user
        except Exception as e:
            await session.rollback()
            raise HTTPException(
                status_code=500,
                detail=f"Ошибка при создании пользователя: {str(e)}"
            )

    @classmethod
    async def authenticate(
        cls, email: str, password: str, session: AsyncSession
    ) -> dict[str, Any]:
        """
        Аутентификация пользователя и генерация токена доступа.
        :param email: email: Email пользователя
        :param password: password: Пароль пользователя
        :param session: session: Сессия базы данных
        :return: str: JWT-токен доступа
        """
        if not email or not password:
            raise HTTPException(
                status_code=400, detail="Email и пароль обязательны"  # Неверный payload
            )
        stmt = (
            select(User)
            .where(User.email == email)
            .options(
                selectinload(User.refresh_tokens)
            )
            .execution_options(populate_existing=True)
        )
        result = await session.execute(stmt)
        user = result.scalar_one_or_none()
        if not user or not cls.verify_password(password, user.pass_hash):
            raise HTTPException(status_code=401, detail="Неверный email или пароль")

        if not user.is_active:
            raise HTTPException(
                status_code=403, detail="Аккаунт деактивирован"  # Доступ запрещён
            )
        access_token = cls.create_access_token({"sub": str(user.id)})
        refresh_token = cls.create_refresh_token(user.id)

        hashed_refresh = pwd_context.hash(refresh_token)
        db_refresh_token = RefreshToken(
            user_id=user.id,
            token_hash=hashed_refresh,
            expires_at=datetime.now(timezone.utc)
            + timedelta(days=settings.auth.REFRESH_EXPIRE_DAYS),
            revoked=False,
        )
        session.add(db_refresh_token)
        await session.commit()

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "user_id": user.id
        }

    @classmethod
    async def check_user_role(
        cls, user_id: int, required_role: str, session: AsyncSession
    ) -> None:
        stmt = select(Role).join(Role.users).where(User.id == user_id)
        result = await session.execute(stmt)
        roles = [r.name for r in result.scalars().all()]
        if required_role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Недостаточно прав"
            )

    @classmethod
    async def verify_refresh_token(
        cls, refresh_token: str, session: AsyncSession
    ) -> Optional[int]:
        """
        Проверяет refresh токен и возвращает user_id, если токен валиден.
        """
        print(">>> Verifying refresh token")
        try:
            payload = jwt.decode(
                refresh_token,
                settings.auth.secret_key,
                algorithms=[settings.auth.algorithm]
            )
            user_id = int(payload.get("sub"))
            if payload.get("type") != "refresh":
                return None
        except (JWTError, ValueError):
            return None

        stmt = select(RefreshToken).where(
            RefreshToken.user_id == user_id,
            RefreshToken.revoked == False,
            RefreshToken.expires_at > datetime.now(timezone.utc),
        )
        result = await session.execute(stmt)
        tokens = result.scalars().all()
        print(f">>> Found {len(tokens)} tokens for user {user_id}")

        for token in tokens:
            if pwd_context.verify(refresh_token, token.token_hash):
                print(">>> Refresh token matched")
                return user_id

        return None
