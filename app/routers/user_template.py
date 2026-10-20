from typing import List

from sqlalchemy.exc import IntegrityError
from fastapi import Depends, HTTPException, APIRouter

from app.db import Session, crud, get_db
from app.models.admin import Admin
from app.models.user_template import (UserTemplateCreate, UserTemplateModify,
                                      UserTemplateResponse)
from app.admin_permissions import fastapi_dep
from app.dependencies import get_user_template

router = APIRouter(tags=['User Template'], prefix='/api')

@router.post("/user_template", response_model=UserTemplateResponse)
def add_user_template(
    new_user_template: UserTemplateCreate,
    db: Session = Depends(get_db),
    admin: Admin = Depends(fastapi_dep("templates", "edit"))
):
    """
    Add a new user template

    - **name** can be up to 64 characters
    - **data_limit** must be in bytes and larger or equal to 0
    - **expire_duration** must be in seconds and larger or equat to 0
    - **inbounds** dictionary of protocol:inbound_tags, empty means all inbounds
    """
    try:
        dbtemplate = crud.create_user_template(db, new_user_template)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Template by this name already exists")
    # f-tplsel-1: respond from the verbatim JSON column (+ bound-user count)
    return UserTemplateResponse.of(dbtemplate)


@router.get("/user_template/{template_id}", response_model=UserTemplateResponse)
def get_user_template_endpoint(
    dbuser_template: UserTemplateResponse = Depends(get_user_template),
    admin: Admin = Depends(Admin.get_current)):
    """Get User Template information with id"""
    return UserTemplateResponse.of(
        dbuser_template,
        users_count=_bound_users_count(db, dbuser_template.id))


@router.put("/user_template/{template_id}", response_model=UserTemplateResponse)
def modify_user_template(
    modify_user_template: UserTemplateModify,
    db: Session = Depends(get_db),
    admin: Admin = Depends(fastapi_dep("templates", "edit")),
    dbuser_template: UserTemplateResponse = Depends(get_user_template)
):
    """
    Modify User Template

    - **name** can be up to 64 characters
    - **data_limit** must be in bytes and larger or equal to 0
    - **expire_duration** must be in seconds and larger or equat to 0
    - **inbounds** dictionary of protocol:inbound_tags, empty means all inbounds
    """
    try:
        dbtemplate = crud.update_user_template(db, dbuser_template, modify_user_template)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Template by this name already exists")
    return UserTemplateResponse.of(dbtemplate)


@router.delete("/user_template/{template_id}")
def remove_user_template(
    db: Session = Depends(get_db),
    admin: Admin = Depends(fastapi_dep("templates", "edit")),
    dbuser_template: UserTemplateResponse = Depends(get_user_template)
):
    """Remove a User Template by its ID"""
    return crud.remove_user_template(db, dbuser_template)


@router.get("/user_template", response_model=List[UserTemplateResponse])
def get_user_templates(
    offset: int = None,
    limit: int = None,
    db: Session = Depends(get_db),
    admin: Admin = Depends(Admin.get_current)
):
    """Get a list of User Templates with optional pagination"""
    from app.db.models import User as LegacyUser
    from sqlalchemy import func

    counts = dict(db.query(LegacyUser.template_id, func.count(LegacyUser.id))
                  .filter(LegacyUser.template_id.isnot(None))
                  .group_by(LegacyUser.template_id).all())
    return [UserTemplateResponse.of(tpl, users_count=counts.get(tpl.id, 0))
            for tpl in crud.get_user_templates(db, offset, limit)]


def _bound_users_count(db: Session, template_id: int) -> int:
    """Users created from this template (bugfix 2: powers the sync prompt)."""
    from app.db.models import User as LegacyUser
    from sqlalchemy import func

    return int(db.query(func.count(LegacyUser.id))
               .filter(LegacyUser.template_id == template_id)
               .scalar() or 0)
