from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from app.core.clock import Clock, SystemClock, to_storage
from app.core.errors import ConflictError, NotFoundError, PermissionDeniedError, ValidationError
from app.core.security import Principal
from app.repositories.business import PetitionRepository
from app.services.access import DataScope
from app.services.audit import AuditContext, AuditService

INBOX_PERMISSIONS = ("petitions.receive", "petitions.write")


class PetitionAccessDenied(PermissionDeniedError):
    """越权访问：仍按原有 403 返回，并携带待落库的 denied 审计载荷。"""

    def __init__(self, message: str, *, audit: dict) -> None:
        super().__init__(message)
        self.audit = audit


def access_denied(
    principal: Principal,
    action: str,
    *,
    resource_id: int | None,
    snapshot: dict | None,
    message: str,
    reason: str,
) -> PetitionAccessDenied:
    return PetitionAccessDenied(
        message,
        audit={
            "context": AuditContext(principal.user_id, principal.display_name),
            "action": action,
            "resource_id": resource_id,
            "before": snapshot,
            "reason": reason,
        },
    )


@dataclass(frozen=True, slots=True)
class Transition:
    source: str
    target: str
    action: str
    # dispatch=True 表示收件箱侧操作（签收/认领/转派/回滚），面向具备收件或写权限的值班角色；
    # 其余为承办部门侧操作，按部门数据范围收紧。
    dispatch: bool = False
    required_permission: str = "petitions.write"


TRANSITIONS = {
    ("待签收", "待分派"): Transition("待签收", "待分派", "信访办签收", dispatch=True, required_permission="petitions.receive"),
    ("待分派", "办理中"): Transition("待分派", "办理中", "认领分派", dispatch=True, required_permission="petitions.receive"),
    ("退回重办", "办理中"): Transition("退回重办", "办理中", "重新分派", dispatch=True, required_permission="petitions.receive"),
    ("办理中", "办理中"): Transition("办理中", "办理中", "转派承办部门", dispatch=True, required_permission="petitions.receive"),
    ("办理中", "待分派"): Transition("办理中", "待分派", "撤回认领回退收件箱", dispatch=True, required_permission="petitions.receive"),
    ("办理中", "待审核"): Transition("办理中", "待审核", "提交办理结果"),
    ("待审核", "已办结"): Transition("待审核", "已办结", "审核通过"),
    ("待审核", "退回重办"): Transition("待审核", "退回重办", "审核退回"),
    ("已办结", "复查中"): Transition("已办结", "复查中", "申请复查"),
    ("复查中", "复查完结"): Transition("复查中", "复查完结", "复查完成"),
}


class PetitionWorkflowService:
    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None) -> None:
        self.connection = connection
        self.clock = clock or SystemClock()
        self.petitions = PetitionRepository(connection)
        self.audit = AuditService(connection, self.clock)

    def visible(self, principal: Principal, petition: dict) -> bool:
        """收件箱（未分派）记录对具备收件或写权限的角色可见；已分派记录按部门收紧；管理员全量。"""
        if not principal.can("petitions.read"):
            return False
        scope = DataScope.from_principal(principal, "petitions.read")
        inbox_permission = next((code for code in INBOX_PERMISSIONS if principal.can(code)), None)
        return scope.can_access_petition(petition, inbox_permission=inbox_permission)

    def require_visible(self, principal: Principal, petition: dict) -> None:
        if self.visible(principal, petition):
            return
        if not principal.can("petitions.read"):
            raise self._denied(principal, "petition.access.denied", petition, "缺少权限：petitions.read", "缺少信访查看权限")
        raise self._denied(principal, "petition.access.denied", petition, "该业务记录不在当前账号的数据范围内", "记录未分派或不属于当前账号的数据范围")

    def transition(
        self,
        principal: Principal,
        petition_id: int,
        target_status: str,
        *,
        department_id: int | None = None,
        result: str | None = None,
        opinion: str | None = None,
        remark: str | None = None,
    ) -> dict:
        petition = self.petitions.detail(petition_id)
        if petition is None:
            raise NotFoundError("信访件不存在")
        transition = TRANSITIONS.get((petition["status"], target_status))
        if transition is None:
            raise ConflictError(f"状态不允许从 {petition['status']} 转到 {target_status}")
        self._authorize(principal, petition, transition)
        if target_status == "办理中":
            if department_id is None:
                raise ValidationError("分派时必须指定承办部门")
            department = self.connection.execute("SELECT id FROM departments WHERE id=? AND is_active=1", (department_id,)).fetchone()
            if department is None:
                raise NotFoundError("承办部门不存在或已停用")
        updates = ["status=?", "updated_at=?"]
        params: list = [target_status, to_storage(self.clock.now())]
        if target_status == "待分派":
            # 回滚认领：解除部门归属并作废原定时限，记录回到未分派收件箱。
            updates.extend(("department_id=?", "deadline=?"))
            params.extend((None, None))
        elif department_id is not None:
            updates.append("department_id=?")
            params.append(department_id)
        if result is not None:
            updates.append("process_result=?")
            params.append(result)
        if opinion is not None:
            updates.append("review_opinion=?")
            params.append(opinion)
        params.append(petition_id)
        self.connection.execute(f"UPDATE petitions SET {','.join(updates)} WHERE id=?", tuple(params))
        self.petitions.append_flow(petition_id, transition.action, principal.display_name, remark or opinion or result, to_storage(self.clock.now()))
        after = self.petitions.detail(petition_id)
        assert after is not None
        self.audit.record(
            AuditContext(principal.user_id, principal.display_name),
            action="petition.transition",
            resource_type="petition",
            resource_id=petition_id,
            before={"status": petition["status"], "department_id": petition["department_id"]},
            after={"status": after["status"], "department_id": after["department_id"]},
            metadata={"flow_action": transition.action},
        )
        return after

    def urge(self, principal: Principal, petition_id: int, reason: str) -> dict:
        petition = self.petitions.detail(petition_id)
        if petition is None:
            raise NotFoundError("信访件不存在")
        self._authorize(principal, petition, None)
        if petition["status"] not in {"办理中", "待审核"}:
            raise ConflictError("当前状态不能催办")
        now = to_storage(self.clock.now())
        cursor = self.connection.execute(
            "INSERT INTO petition_urges(petition_id,reason,operator,created_at) VALUES(?,?,?,?)",
            (petition_id, reason.strip(), principal.display_name, now),
        )
        self.petitions.append_flow(petition_id, "催办", principal.display_name, reason.strip(), now)
        return dict(self.connection.execute("SELECT * FROM petition_urges WHERE id=?", (cursor.lastrowid,)).fetchone())

    # ------------------------------------------------------------------
    # 权限边界
    # ------------------------------------------------------------------

    def _authorize(self, principal: Principal, petition: dict, transition: Transition | None) -> None:
        """统一的访问入口：未分派走收件箱权限，认领后立即按部门范围收紧。"""
        if principal.can("*"):
            return
        dispatch = transition is not None and transition.dispatch

        if dispatch:
            # 收件箱操作（签收/认领/转派/回滚）：具备收件或写权限即可，不受当前部门归属限制。
            if not any(principal.can(code) for code in INBOX_PERMISSIONS):
                action = "petition.transition.denied"
                raise self._denied(principal, action, petition, f"缺少权限：{transition.required_permission}", "缺少收件箱收件或写入权限")
            return

        # 承办部门侧操作必须持有写权限。
        if not principal.can("petitions.write"):
            action = "petition.transition.denied" if transition is not None else "petition.urge.denied"
            raise self._denied(principal, action, petition, "缺少权限：petitions.write", "缺少信访写入权限")
        scope = DataScope.from_principal(principal, "petitions.write")
        if not scope.can_access_petition(petition, inbox_permission=None):
            reason = "记录尚未分派，部门账号不能办理" if petition["department_id"] is None else "记录属于其他部门"
            action = "petition.transition.denied" if transition is not None else "petition.urge.denied"
            raise self._denied(principal, action, petition, "该业务记录不在当前账号的数据范围内", reason)

    def _denied(self, principal: Principal, action: str, petition: dict, message: str, reason: str) -> PetitionAccessDenied:
        return access_denied(
            principal,
            action,
            resource_id=petition.get("id"),
            snapshot={"status": petition.get("status"), "department_id": petition.get("department_id")},
            message=message,
            reason=reason,
        )
