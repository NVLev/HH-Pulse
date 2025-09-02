from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, Boolean, UniqueConstraint, Index
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func
from sqlalchemy.dialects.postgresql import UUID, JSON
from enum import Enum
from sqlalchemy.dialects.postgresql import ENUM as PgEnum
import uuid

Base = declarative_base()

class VacancyStatus(str, Enum):
    SAVED = "saved"
    APPLIED = "applied"
    REJECTED = "rejected"
    INTERVIEWING = "interviewing"
    OFFER = "offer"

class VacancySource(str, Enum):
    HH = "hh"
    SUPERJOB = "superjob"
    LINKEDIN = "linkedin"
    OTHER = "other"

class User(Base):
    """
        Модель пользователя  с email b хешированным паролем

        Атрибуты:
            id (int): Уникальный идентификатор
            public_user_id (int):  используется для связи с Телеграм ботом
            email (str): Уникальный email
            pass_hash (str): Хешированный пароль
            hh_... :  данные из hh.ru, для расширения возможностей сервиса
            search_filters (dict): настройки поиска
        """

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    public_user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), unique=True, default=uuid.uuid4
    )

    # Данные для локальной авторизации
    email: Mapped[Optional[str]] = mapped_column(String, unique=True, index=True)
    pass_hash: Mapped[Optional[str]] = mapped_column(String)

    # Токены для API
    refresh_tokens: Mapped[list["RefreshToken"]] = relationship(
        "RefreshToken",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    # Данные из hh.ru (если юзер залогинился через hh)
    hh_user_id: Mapped[Optional[int]] = mapped_column(Integer, unique=True)
    hh_full_name: Mapped[Optional[str]] = mapped_column(String)
    hh_access_token: Mapped[Optional[str]] = mapped_column(String)
    hh_refresh_token: Mapped[Optional[str]] = mapped_column(String)
    hh_token_expires: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    # Настройки
    search_filters: Mapped[dict] = mapped_column(JSON, default={})
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    def __repr__(self):
        return f"<User(id={self.id}, email='{self.email}', public_id='{self.public_user_id}')>"

class RefreshToken(Base):
    """
        Модель для хранения токенов
        Атрибуты:
            user_id (int): Уникальный идентификатор
            role_id:
        """

    __tablename__ = "refresh_tokens"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(
    ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    token_hash: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    expires_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), default=lambda: func.now() + timedelta(days=7)
    )
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    user: Mapped["User"] = relationship("User", back_populates="refresh_tokens")

    def __repr__(self):
        return f"<RefreshToken(id={self.id}, user_id={self.user_id}, revoked={self.revoked})>"




# модель для связи пользователей с вакансиями
class UserVacancy(Base):
    """
    Связь пользователя с вакансиями (избранные, отклики, заметки)
    """

    __tablename__ = "user_vacancies"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    vacancy_id: Mapped[int] = mapped_column(ForeignKey("vacancies.id", ondelete="CASCADE"), nullable=False)

    # Статус взаимодействия
    status: Mapped[VacancyStatus] = mapped_column(String(50), default=VacancyStatus.SAVED, index=True)

    # Метаданные
    notes: Mapped[Optional[str]] = mapped_column(Text)
    applied_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(),
                                                 onupdate=func.now())

    # Связи
    user: Mapped["User"] = relationship("User", back_populates="user_vacancies")
    vacancy: Mapped["Vacancy"] = relationship("Vacancy")

    __table_args__ = (
        UniqueConstraint("user_id", "vacancy_id", name="uq_user_vacancy"),
        Index("idx_user_status", "user_id", "status"),
    )

class Vacancy(Base):
    """
    Модель вакансии с расширенными полями и индексами
    """

    __tablename__ = "vacancies"

    id: Mapped[int] = mapped_column(primary_key=True)

    # Основная информация
    source: Mapped["VacancySource"] = mapped_column(
        PgEnum(VacancySource, name="vacancy_source"),
        nullable=False,
        index=True
    )

    external_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    company: Mapped[str] = mapped_column(String(255), nullable=False, index=True)

    # Локация
    city: Mapped[Optional[str]] = mapped_column(String(100), index=True)
    remote_work: Mapped[bool] = mapped_column(Boolean, default=False, index=True)

    # Контент
    url: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    requirements: Mapped[Optional[str]] = mapped_column(Text)

    # Зарплата (структурированно)
    salary: Mapped[Optional[str]] = mapped_column(String(100), index=True)
    currency: Mapped[Optional[str]] = mapped_column(String(3), default="RUB")

    # Дополнительные поля
    experience: Mapped[Optional[str]] = mapped_column(String(50))
    employment_type: Mapped[Optional[str]] = mapped_column(String(50))
    schedule: Mapped[Optional[str]] = mapped_column(String(50))
    skills: Mapped[Optional[List[str]]] = mapped_column(JSON)

    # Метаданные
    published_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    # Индексы и ограничения
    __table_args__ = (
        UniqueConstraint("source", "external_id", name="uq_source_extid"),
        Index("idx_vacancy_search", "title", "company", "city"),
        Index("idx_vacancy_salary", "salary_from", "salary_to"),
        Index("idx_vacancy_published", "published_at", "source"),
    )

    def __repr__(self):
        return f"<Vacancy(id={self.id}, title='{self.title}', company='{self.company}')>"


# Модель для хранения поисковых запросов пользователей

class UserSearchQuery(Base):
    """
    Сохраненные поисковые запросы пользователей для уведомлений
    """

    __tablename__ = "user_search_queries"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # Параметры поиска
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    query_params: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False)

    # Настройки уведомлений
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    notification_frequency: Mapped[str] = mapped_column(String(20), default="daily")
    last_notified: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    # Метаданные
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now()
    )

    # Связи
    user: Mapped["User"] = relationship("User")

    __table_args__ = (
        Index("idx_user_active_queries", "user_id", "is_active"),
    )

