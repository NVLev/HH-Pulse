from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

from ..config import settings
from ..services.hh_oauth import HHOAuthClient
from ..services.auth_service import AuthService
from ..core.models import User
from ..core.schemas import UserRead, UserCreate
from ..core.db_helper import db_helper

router = APIRouter(prefix="/auth", tags=["Auth"])
hh_oauth = HHOAuthClient()

@router.post("/register", response_model=UserRead)
async def register(
    user_data: UserCreate, session: AsyncSession = Depends(db_helper.session_getter)
):
    try:
        user = await AuthService.register(user_data, session)

        stmt = select(User).options(selectinload(User.roles)).where(User.id == user.id)
        result = await session.execute(stmt)
        user_with_roles = result.scalar_one()

        roles = [role.name for role in user_with_roles.roles]

        return {
            "id": user_with_roles.id,
            "email": user_with_roles.email,
            "is_active": user_with_roles.is_active,
            "created_at": user_with_roles.created_at,
        }
    except HTTPException as e:
        raise e
    except Exception as e:
        import traceback

        print("Ошибка:", e)
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="Ошибка сервера")
