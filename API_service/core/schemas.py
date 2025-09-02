import json
import re
from enum import Enum
from pydantic import BaseModel, EmailStr, Field, field_validator
from pydantic.config import ConfigDict
from datetime import datetime
from typing import List, Optional, Dict, Any, Union
from .models import VacancySource




class UserBase(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class UserCreate(UserBase):
    email: EmailStr
    password: str = Field(..., min_length=8)

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        pattern = r'^(?=.*[a-zа-я])(?=.*[A-ZА-Я])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>?]).{8,}$'
        if not re.match(pattern, v):
            raise ValueError("Пароль должен содержать строчную и заглавную буквы, цифру и спецсимвол")
        return v

class UserUpdate(UserBase):
    """Схема для обновления данных пользователя"""
    email: Optional[EmailStr] = None
    password: Optional[str] = Field(None, min_length=8)
    is_active: Optional[bool] = None
    search_filters: Optional[Dict[str, Any]] = None

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        pattern = r'^(?=.*[a-zа-я])(?=.*[A-ZА-Я])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>?]).{8,}$'
        if not re.match(pattern, v):
            raise ValueError("Пароль должен содержать строчную и заглавную буквы, цифру и спецсимвол")
        return v

class UserRead(UserBase):
    """
    Схема для чтения данных пользователя (публичная информация)
    """

    id: int = Field(..., description="Уникальный идентификатор пользователя")
    public_user_id: str = Field(..., description="Публичный идентификатор пользователя")
    email: EmailStr = Field(..., description="Email пользователя")
    is_active: bool = Field(..., description="Активен ли аккаунт")
    created_at: datetime = Field(..., description="Дата и время создания аккаунта")
    search_filters: Dict[str, Any] = Field(default={}, description="Настройки поиска")

class UserProfile(UserRead):
    """Полная схема профиля пользователя (включая данные hh.ru)"""
    hh_user_id: Optional[int] = Field(None, description="ID пользователя в hh.ru")
    hh_full_name: Optional[str] = Field(None, description="Полное имя из hh.ru")
    hh_token_expires: Optional[datetime] = Field(None, description="Срок действия токена hh.ru")


class UserInDB(UserProfile):
    """Схема для внутреннего использования (с хешем пароля)"""
    pass_hash: Optional[str] = Field(None, description="Хешированный пароль")


# Схемыы интерграции с hh

class HHUserInfo(BaseModel):
    """Информация о пользователе из hh.ru"""
    hh_user_id: int = Field(..., description="ID пользователя в hh.ru")
    hh_full_name: str = Field(..., description="Полное имя пользователя")
    email: Optional[EmailStr] = Field(None, description="Email из hh.ru")

class HHTokenData(BaseModel):
    """Токены от hh.ru"""
    access_token: str = Field(..., description="Access token hh.ru")
    refresh_token: str = Field(..., description="Refresh token hh.ru")
    expires_in: int = Field(..., description="Время жизни токена в секундах")


class HHAuthCallback(BaseModel):
    """Данные от callback hh.ru OAuth"""
    code: str = Field(..., description="Authorization code от hh.ru")
    state: Optional[str] = Field(None, description="State parameter")


class Token(BaseModel):
    access_token: str = Field(..., description="JWT access token")
    token_type: str = Field(default="bearer", description="Тип токена")
    refresh_token: Optional[str] = Field(None, description="Refresh token")


class TokenPayload(BaseModel):
    sub: Optional[int] = None
    exp: Optional[int] = None
    iat: Optional[int] = Field(None, description="Issued at timestamp")
    type: str = Field(default="access", description="Тип токена")


class TokenResponse(BaseModel):
    access_token: str = Field(..., description="JWT access token")
    refresh_token: str = Field(..., description="Refresh token")
    token_type: str = Field(default="bearer", description="Тип токена")

class RefreshTokenRequest(BaseModel):
    refresh_token: str

class VacancyBase(BaseModel):
    """Базовая схема вакансии"""
    model_config = ConfigDict(from_attributes=True)


class VacancyCreate(VacancyBase):
    """Схема для создания вакансии"""
    source: VacancySource = Field(..., description="Источник вакансии")
    external_id: str = Field(..., description="ID в системе источника")
    title: str = Field(..., description="Название вакансии")
    company: str = Field(..., description="Название компании")
    city: Optional[str] = Field(None, description="Город")
    url: str = Field(..., description="Ссылка на вакансию")
    salary: Optional[str] = Field(None, description="Зарплата")
    currency: Optional[str] = "RUB"
    skills: Optional[Dict[str, Any]] = Field(None, description="Требуемые навыки")

class VacancyUpdate(VacancyBase):
    """Схема для обновления вакансии"""
    title: Optional[str] = Field(None, description="Название вакансии")
    company: Optional[str] = Field(None, description="Название компании")
    city: Optional[str] = Field(None, description="Город")
    url: Optional[str] = Field(None, description="Ссылка на вакансию")
    salary: Optional[str] = Field(None, description="Зарплата")
    skills: Optional[Dict[str, Any]] = Field(None, description="Требуемые навыки")


class VacancyRead(VacancyBase):
    """Схема для чтения вакансии"""
    id: int = Field(..., description="Уникальный идентификатор")
    source: VacancySource = Field(..., description="Источник вакансии")
    external_id: str = Field(..., description="ID в системе источника")
    title: str = Field(..., description="Название вакансии")
    company: str = Field(..., description="Название компании")
    city: Optional[str] = Field(None, description="Город")
    url: str = Field(..., description="Ссылка на вакансию")
    salary: Optional[str] = Field(None, description="Зарплата")
    skills: Optional[Dict[str, Any]] = Field(None, description="Требуемые навыки")
    created_at: datetime = Field(..., description="Дата создания записи")


class VacancyList(BaseModel):
    """Список вакансий с пагинацией"""
    items: List[VacancyRead] = Field(..., description="Список вакансий")
    total: int = Field(..., description="Общее количество")
    page: int = Field(..., description="Номер страницы")
    size: int = Field(..., description="Размер страницы")
    pages: int = Field(..., description="Общее количество страниц")

class VacancySearchFilters(BaseModel):
    """Фильтры поиска вакансий"""
    query: Optional[str] = Field(None, description="Поисковый запрос")
    city: Optional[str] = Field(None, description="Город")
    salary_from: Optional[int] = Field(None, description="Зарплата от")
    salary_to: Optional[int] = Field(None, description="Зарплата до")
    source: Optional[VacancySource] = Field(None, description="Источник")
    skills: Optional[List[str]] = Field(None, description="Требуемые навыки")
    company: Optional[str] = Field(None, description="Компания")


class VacancySearchRequest(VacancySearchFilters):
    """Запрос поиска вакансий с пагинацией"""
    page: int = Field(default=1, ge=1, description="Номер страницы")
    size: int = Field(default=20, ge=1, le=100, description="Размер страницы")
    sort_by: Optional[str] = Field(default="created_at", description="Поле сортировки")
    sort_order: str = Field(default="desc", regex="^(asc|desc)$", description="Порядок сортировки")

class LoginRequest(BaseModel):
    """Запрос на авторизацию"""
    email: EmailStr = Field(..., description="Email пользователя")
    password: str = Field(..., description="Пароль")


class LoginResponse(BaseModel):
    """Ответ на авторизацию"""
    access_token: str = Field(..., description="JWT access token")
    refresh_token: str = Field(..., description="Refresh token")
    token_type: str = Field(default="bearer", description="Тип токена")
    expires_in: int = Field(default=3600, description="Время жизни access token")
    user: UserRead = Field(..., description="Данные пользователя")

class LogoutRequest(BaseModel):
    """Запрос на выход"""
    refresh_token: Optional[str] = Field(None, description="Refresh token для отзыва")


class ErrorDetail(BaseModel):
    """Детали ошибки"""
    message: str = Field(..., description="Сообщение об ошибке")
    code: Optional[str] = Field(None, description="Код ошибки")
    field: Optional[str] = Field(None, description="Поле, вызвавшее ошибку")


class ErrorResponse(BaseModel):
    """Стандартный ответ с ошибкой"""
    detail: Union[str, List[ErrorDetail]] = Field(..., description="Детали ошибки")
    error_code: Optional[str] = Field(None, description="Код ошибки")

