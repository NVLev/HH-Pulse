# - функция для обмена authorization code на access_token и refresh_token (POST к token_url).
# - функция для обновления токена (если истёк).
from authlib.integrations.httpx_client import AsyncOAuth2Client
from datetime import datetime, timedelta
from ..config import settings


class HHOAuthClient:
    def __init__(self):
        self.client = AsyncOAuth2Client(
            client_id=settings.hh.client_id,
            client_secret=settings.hh.client_secret,
            redirect_uri=settings.hh.redirect_uri,
        )
        self.auth_url = settings.hh.auth_url
        self.token_url = settings.hh.token_url

    async def get_authorization_url(self):
        """Сформировать URL для авторизации на hh.ru"""
        authorization_url, state = self.client.create_authorization_url(
            self.auth_url,
            response_type="code"
        )
        return authorization_url, state

    async def exchange_code_for_tokens(self, code: str):
        """Обменять code на access/refresh токены"""
        token = await self.client.fetch_token(
            self.token_url,
            code=code,
            client_secret=settings.hh.client_secret,
            redirect_uri=settings.hh.redirect_uri,
        )
        return {
            "access_token": token["access_token"],
            "refresh_token": token["refresh_token"],
            "token_type": token.get("token_type", "bearer"),
            "expires_at": datetime.utcnow() + timedelta(seconds=token["expires_in"]),
        }

    async def refresh_access_token(self, refresh_token: str):
        """Обновить access token"""
        new_token = await self.client.refresh_token(
            self.token_url,
            refresh_token=refresh_token,
            client_id=settings.hh.client_id,
            client_secret=settings.hh.client_secret,
        )
        return {
            "access_token": new_token["access_token"],
            "refresh_token": new_token.get("refresh_token", refresh_token),
            "token_type": new_token.get("token_type", "bearer"),
            "expires_at": datetime.utcnow() + timedelta(seconds=new_token["expires_in"]),
        }
