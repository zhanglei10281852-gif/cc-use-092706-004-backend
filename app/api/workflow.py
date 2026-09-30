from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from app.api.dependencies import current_principal
from app.core.errors import NotFoundError
from app.core.security import Principal
from app.database import get_connection, transaction
from app.repositories.business import PetitionRepository
from app.schemas.business import PetitionTransitionRequest, UrgeRequest
from app.services.audit import AuditService
from app.services.workflow import INBOX_PERMISSIONS, PetitionAccessDenied, PetitionWorkflowService, access_denied

router = APIRouter(prefix="/api/petition-workflow", tags=["信访协作"])


def _has_inbox_permission(principal: Principal) -> bool:
    return any(principal.can(code) for code in INBOX_PERMISSIONS)


def _persist_denial(exc: PetitionAccessDenied) -> None:
    """业务事务回滚后再落 denied 审计，保证越权访问不丢失审计痕迹。"""
    payload = exc.audit
    with transaction() as connection:
        AuditService(connection).record(
            payload["context"],
            action=payload["action"],
            resource_type="petition",
            resource_id=payload["resource_id"],
            outcome="denied",
            before=payload["before"],
            metadata={"reason": payload["reason"]},
        )


def _audit_and_raise(principal: Principal, message: str, reason: str) -> None:
    raise access_denied(
        principal,
        "petition.list.denied",
        resource_id=None,
        snapshot=None,
        message=message,
        reason=reason,
    )


@router.get("")
def list_petitions(
    department_id: int | None = None,
    status: list[str] | None = Query(default=None),
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    principal: Principal = Depends(current_principal),
) -> dict:
    try:
        if not principal.can("petitions.read"):
            _audit_and_raise(principal, "缺少权限：petitions.read", "缺少信访查看权限")
        if principal.can("*"):
            scope_mode = "all"
        elif principal.department_id is None:
            scope_mode = "self"
        else:
            scope_mode = "department"
        can_inbox = _has_inbox_permission(principal)
        repository = PetitionRepository(get_connection())
        if scope_mode == "all":
            # 管理员全量视图保持不变。
            kwargs = dict(department_id=department_id, unscoped=True)
        elif scope_mode == "self":
            # 无部门账号（值班/信访办）仅能看到未分派收件箱，且必须具备收件或写权限。
            if department_id is not None:
                _audit_and_raise(principal, "当前账号没有部门数据范围", "无部门账号不能按部门筛选")
            kwargs = dict(department_id=None, include_unassigned=can_inbox)
        else:
            # 部门账号：本部门记录 + 未分派收件箱（须具备收件/写权限）。
            if department_id not in {None, principal.department_id}:
                _audit_and_raise(principal, "不能访问其他部门的数据", "请求了其他部门的筛选范围")
            kwargs = dict(department_id=principal.department_id, include_unassigned=can_inbox)
        rows = repository.list_for_scope(
            statuses=status,
            deadline_before=None,
            limit=size,
            offset=(page - 1) * size,
            **kwargs,
        )
    except PetitionAccessDenied as exc:
        _persist_denial(exc)
        raise
    return {"page": page, "size": size, "data": rows}


@router.get("/{petition_id}")
def get_petition(petition_id: int, principal: Principal = Depends(current_principal)) -> dict:
    try:
        with transaction() as connection:
            service = PetitionWorkflowService(connection)
            petition = service.petitions.detail(petition_id)
            if petition is None:
                raise NotFoundError("信访件不存在")
            # 未分派记录仅对收件/写权限角色可见；认领后按部门收紧；越权返回原错误并写审计。
            service.require_visible(principal, petition)
            return petition
    except PetitionAccessDenied as exc:
        _persist_denial(exc)
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
    except PetitionAccessDenied as exc:
        _persist_denial(exc)
        raise


@router.post("/{petition_id}/urge", status_code=201)
def urge(petition_id: int, data: UrgeRequest, principal: Principal = Depends(current_principal)) -> dict:
    try:
        with transaction(immediate=True) as connection:
            return PetitionWorkflowService(connection).urge(principal, petition_id, data.reason)
    except PetitionAccessDenied as exc:
        _persist_denial(exc)
        raise
