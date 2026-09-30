from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from app.api.dependencies import current_principal
from app.core.errors import PermissionDeniedError
from app.core.security import Principal
from app.database import get_connection, transaction
from app.repositories.business import PetitionRepository
from app.schemas.business import (
    PetitionTransitionRequest,
    ReassignRequest,
    RollbackRequest,
    UrgeRequest,
)
from app.services.access import INBOX_PERMISSION, WRITE_PERMISSION, DataScope
from app.services.audit import AuditContext, AuditService
from app.services.workflow import PetitionWorkflowService

router = APIRouter(prefix="/api/petition-workflow", tags=["信访协作"])


def _can_review_inbox(principal: Principal) -> bool:
    return principal.can(INBOX_PERMISSION) or principal.can(WRITE_PERMISSION)


def _record_denial(principal: Principal, action: str, petition_id: int | None, reason: str) -> None:
    """越权访问在业务事务回滚后单独落审计，保证拒绝记录不丢失。"""
    with transaction() as connection:
        AuditService(connection).record(
            AuditContext(principal.user_id, principal.display_name),
            action=action,
            resource_type="petition",
            resource_id=petition_id,
            outcome="denied",
            metadata={"reason": reason},
        )


@router.get("")
def list_petitions(
    department_id: int | None = None,
    status: list[str] | None = Query(default=None),
    inbox: bool = Query(default=False, description="仅查看未分派收件箱"),
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    principal: Principal = Depends(current_principal),
) -> dict:
    try:
        return _list_petitions(principal, department_id, status, inbox, page, size)
    except PermissionDeniedError as exc:
        _record_denial(principal, "petition.list_inbox" if inbox else "petition.list", None, exc.message)
        raise


def _list_petitions(
    principal: Principal,
    department_id: int | None,
    status: list[str] | None,
    inbox: bool,
    page: int,
    size: int,
) -> dict:
    inbox_allowed = _can_review_inbox(principal)
    repository = PetitionRepository(get_connection())

    if inbox:
        # 收件箱：只返回未分派记录，仅收件/写入角色可见
        if not inbox_allowed:
            raise PermissionDeniedError("缺少权限：petitions.inbox")
        rows = repository.list_for_scope(
            department_id=None,
            statuses=status,
            deadline_before=None,
            limit=size,
            offset=(page - 1) * size,
            unassigned="only",
        )
        return {"page": page, "size": size, "data": rows}

    scope = DataScope.from_principal(principal, "petitions.read")
    if scope.mode == "all":
        # 管理员全量视图：未分派与历史已分派记录均可见
        effective_department = department_id
        unassigned = "include"
    elif scope.mode == "department":
        effective_department = scope.restrict_department(department_id)
        # 本部门已分派记录；具备收件/写入权限时额外可见未分派收件箱
        unassigned = "include" if inbox_allowed else "exclude"
    else:
        # 无部门范围的只读账号只能看已分派记录，不允许按部门筛选
        if department_id is not None:
            raise PermissionDeniedError("当前账号没有部门数据范围")
        effective_department = None
        unassigned = "include" if inbox_allowed else "exclude"

    rows = repository.list_for_scope(
        department_id=effective_department,
        statuses=status,
        deadline_before=None,
        limit=size,
        offset=(page - 1) * size,
        unassigned=unassigned,
    )
    return {"page": page, "size": size, "data": rows}


@router.get("/{petition_id}")
def get_petition(petition_id: int, principal: Principal = Depends(current_principal)) -> dict:
    try:
        with transaction() as connection:
            return PetitionWorkflowService(connection).view(principal, petition_id)
    except PermissionDeniedError as exc:
        _record_denial(principal, "petition.view", petition_id, exc.message)
        raise


@router.post("/{petition_id}/transition")
def transition(petition_id: int, data: PetitionTransitionRequest, principal: Principal = Depends(current_principal)) -> dict:
    try:
        with transaction(immediate=True) as connection:
            return PetitionWorkflowService(connection).transition(
                principal,
                petition_id,
                data.target_status,
                department_id=data.department_id,
                result=data.result,
                opinion=data.opinion,
                remark=data.remark,
            )
    except PermissionDeniedError as exc:
        _record_denial(principal, "petition.transition", petition_id, exc.message)
        raise


@router.post("/{petition_id}/reassign")
def reassign(petition_id: int, data: ReassignRequest, principal: Principal = Depends(current_principal)) -> dict:
    try:
        with transaction(immediate=True) as connection:
            return PetitionWorkflowService(connection).reassign(principal, petition_id, data.department_id, data.reason)
    except PermissionDeniedError as exc:
        _record_denial(principal, "petition.reassign", petition_id, exc.message)
        raise


@router.post("/{petition_id}/rollback")
def rollback(petition_id: int, data: RollbackRequest, principal: Principal = Depends(current_principal)) -> dict:
    try:
        with transaction(immediate=True) as connection:
            return PetitionWorkflowService(connection).rollback(principal, petition_id, data.reason)
    except PermissionDeniedError as exc:
        _record_denial(principal, "petition.rollback", petition_id, exc.message)
        raise


@router.post("/{petition_id}/urge", status_code=201)
def urge(petition_id: int, data: UrgeRequest, principal: Principal = Depends(current_principal)) -> dict:
    try:
        with transaction(immediate=True) as connection:
            return PetitionWorkflowService(connection).urge(principal, petition_id, data.reason)
    except PermissionDeniedError as exc:
        _record_denial(principal, "petition.urge", petition_id, exc.message)
        raise
