from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from app.core.clock import Clock, SystemClock, to_storage
from app.core.errors import ConflictError, NotFoundError, PermissionDeniedError, ValidationError
from app.core.security import Principal
from app.repositories.business import PetitionRepository
from app.services.access import INBOX_PERMISSION, WRITE_PERMISSION, DataScope
from app.services.audit import AuditContext, AuditService


@dataclass(frozen=True, slots=True)
class Transition:
    source: str
    target: str
    action: str
    required_permission: str = "petitions.write"


TRANSITIONS = {
    ("待签收", "待分派"): Transition("待签收", "待分派", "信访办签收"),
    ("待分派", "办理中"): Transition("待分派", "办理中", "分派承办"),
    ("退回重办", "办理中"): Transition("退回重办", "办理中", "重新分派"),
    ("办理中", "待审核"): Transition("办理中", "待审核", "提交办理结果"),
    ("待审核", "已办结"): Transition("待审核", "已办结", "审核通过"),
    ("待审核", "退回重办"): Transition("待审核", "退回重办", "审核退回"),
    ("已办结", "复查中"): Transition("已办结", "复查中", "申请复查"),
    ("复查中", "复查完结"): Transition("复查中", "复查完结", "复查完成"),
}

# 回滚：撤销最近一次业务动作，记录回到上一个工作流节点
ROLLBACK_STEPS = {
    "办理中": ("待分派", "撤回认领", ("department_id", "deadline")),
    "待审核": ("办理中", "撤回办理结果", ("process_result",)),
}

# 进入“办理中”即认领/分派（从收件箱或退回重办）
DISPATCH_STATUSES = {"待分派", "退回重办"}


class PetitionWorkflowService:
    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None) -> None:
        self.connection = connection
        self.clock = clock or SystemClock()
        self.petitions = PetitionRepository(connection)
        self.audit = AuditService(connection, self.clock)

    def view(self, principal: Principal, petition_id: int) -> dict:
        """读取单个信访件，按收件箱/部门范围授权。"""
        petition = self.petitions.detail(petition_id)
        if petition is None:
            raise NotFoundError("信访件不存在")
        if not (principal.can("petitions.read") or principal.can(INBOX_PERMISSION) or principal.can(WRITE_PERMISSION)):
            raise PermissionDeniedError("缺少权限：petitions.read")
        permission = next(
            (code for code in ("petitions.read", WRITE_PERMISSION, INBOX_PERMISSION) if principal.can(code)),
            "petitions.read",
        )
        scope = DataScope.from_principal(principal, permission)
        scope.authorize_petition(principal, petition["department_id"])
        return petition

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
        is_dispatch = target_status == "办理中" and petition["status"] in DISPATCH_STATUSES
        if is_dispatch:
            # 认领/分派：值班收件角色或写入角色均可操作
            principal.require_any(INBOX_PERMISSION, WRITE_PERMISSION)
            gate_permission = INBOX_PERMISSION if principal.can(INBOX_PERMISSION) else WRITE_PERMISSION
        else:
            principal.require(transition.required_permission)
            gate_permission = transition.required_permission
        scope = DataScope.from_principal(principal, gate_permission)
        # 未分派记录对收件/写入角色开放；已分派记录立即按部门范围收紧
        scope.authorize_petition(principal, petition["department_id"], for_write=True)
        if target_status == "办理中":
            if department_id is None:
                raise ValidationError("分派时必须指定承办部门")
            department = self.connection.execute("SELECT id FROM departments WHERE id=? AND is_active=1", (department_id,)).fetchone()
            if department is None:
                raise NotFoundError("承办部门不存在或已停用")
            # 非调度角色只能认领到本部门
            if not principal.can(INBOX_PERMISSION) and scope.mode != "all":
                scope.restrict_department(department_id)
        updates = ["status=?", "updated_at=?"]
        params: list = [target_status, to_storage(self.clock.now())]
        if department_id is not None:
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

    def reassign(self, principal: Principal, petition_id: int, new_department_id: int, reason: str | None = None) -> dict:
        """转派：仅收件调度角色或管理员可跨部门改派，改派后立即按新部门收紧。"""
        petition = self.petitions.detail(petition_id)
        if petition is None:
            raise NotFoundError("信访件不存在")
        principal.require_any(INBOX_PERMISSION, WRITE_PERMISSION)
        if not (principal.can(INBOX_PERMISSION) or "*" in principal.permissions):
            raise PermissionDeniedError("转派需要信访收件箱调度权限")
        if petition["status"] not in {"办理中", "待审核"}:
            raise ConflictError("当前状态不允许转派")
        if petition["department_id"] == new_department_id:
            raise ValidationError("转派目标部门与当前承办部门相同")
        department = self.connection.execute("SELECT id,name FROM departments WHERE id=? AND is_active=1", (new_department_id,)).fetchone()
        if department is None:
            raise NotFoundError("承办部门不存在或已停用")
        now = to_storage(self.clock.now())
        self.connection.execute(
            "UPDATE petitions SET department_id=?,updated_at=? WHERE id=?",
            (new_department_id, now, petition_id),
        )
        remark = f"转派至{department['name']}" + (f"：{reason.strip()}" if reason else "")
        self.petitions.append_flow(petition_id, "转派", principal.display_name, remark, now)
        after = self.petitions.detail(petition_id)
        assert after is not None
        self.audit.record(
            AuditContext(principal.user_id, principal.display_name),
            action="petition.reassign",
            resource_type="petition",
            resource_id=petition_id,
            before={"department_id": petition["department_id"], "department_name": petition.get("department_name")},
            after={"department_id": after["department_id"], "department_name": after.get("department_name")},
            metadata={"reason": reason.strip() if reason else ""},
        )
        return after

    def rollback(self, principal: Principal, petition_id: int, reason: str | None = None) -> dict:
        """回滚最近一次动作：办理中→待分派（撤回认领）、待审核→办理中（撤回结果）。"""
        petition = self.petitions.detail(petition_id)
        if petition is None:
            raise NotFoundError("信访件不存在")
        principal.require_any(INBOX_PERMISSION, WRITE_PERMISSION)
        step = ROLLBACK_STEPS.get(petition["status"])
        if step is None:
            raise ConflictError(f"当前状态 {petition['status']} 不允许回滚")
        target_status, action, cleared_fields = step
        gate_permission = INBOX_PERMISSION if principal.can(INBOX_PERMISSION) else WRITE_PERMISSION
        scope = DataScope.from_principal(principal, gate_permission)
        # 撤回认领把记录退回未分派收件箱，需调度权限；非调度角色仅能回滚本部门记录
        scope.authorize_petition(principal, petition["department_id"], for_write=True)
        now = to_storage(self.clock.now())
        assignments = ["status=?", "updated_at=?"] + [f"{field}=NULL" for field in cleared_fields]
        self.connection.execute(
            f"UPDATE petitions SET {','.join(assignments)} WHERE id=?",
            (target_status, now, petition_id),
        )
        self.petitions.append_flow(petition_id, action, principal.display_name, reason.strip() if reason else None, now)
        after = self.petitions.detail(petition_id)
        assert after is not None
        self.audit.record(
            AuditContext(principal.user_id, principal.display_name),
            action="petition.rollback",
            resource_type="petition",
            resource_id=petition_id,
            before={"status": petition["status"], "department_id": petition["department_id"]},
            after={"status": after["status"], "department_id": after["department_id"]},
            metadata={"flow_action": action, "reason": reason.strip() if reason else ""},
        )
        return after

    def urge(self, principal: Principal, petition_id: int, reason: str) -> dict:
        petition = self.petitions.detail(petition_id)
        if petition is None:
            raise NotFoundError("信访件不存在")
        principal.require("petitions.write")
        scope = DataScope.from_principal(principal, "petitions.write")
        scope.authorize_petition(principal, petition["department_id"], for_write=True)
        if petition["status"] not in {"办理中", "待审核"}:
            raise ConflictError("当前状态不能催办")
        now = to_storage(self.clock.now())
        cursor = self.connection.execute(
            "INSERT INTO petition_urges(petition_id,reason,operator,created_at) VALUES(?,?,?,?)",
            (petition_id, reason.strip(), principal.display_name, now),
        )
        self.petitions.append_flow(petition_id, "催办", principal.display_name, reason.strip(), now)
        self.audit.record(
            AuditContext(principal.user_id, principal.display_name),
            action="petition.urge",
            resource_type="petition",
            resource_id=petition_id,
            metadata={"reason": reason.strip()},
        )
        return dict(self.connection.execute("SELECT * FROM petition_urges WHERE id=?", (cursor.lastrowid,)).fetchone())
