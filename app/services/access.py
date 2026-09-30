from __future__ import annotations

from dataclasses import dataclass

from app.core.errors import PermissionDeniedError
from app.core.security import Principal

# 未分派收件箱记录的可见角色：具备收件权限或写入权限的账号
INBOX_PERMISSION = "petitions.inbox"
WRITE_PERMISSION = "petitions.write"

OUT_OF_SCOPE_MESSAGE = "该业务记录不在当前账号的数据范围内"


@dataclass(frozen=True, slots=True)
class DataScope:
    mode: str
    department_id: int | None

    @classmethod
    def from_principal(cls, principal: Principal, permission: str) -> "DataScope":
        if "*" in principal.permissions:
            return cls("all", None)
        if permission not in principal.permissions:
            raise PermissionDeniedError(f"缺少权限：{permission}")
        if principal.department_id is None:
            return cls("self", None)
        return cls("department", principal.department_id)

    def restrict_department(self, requested_department_id: int | None) -> int | None:
        if self.mode == "all":
            return requested_department_id
        if self.mode == "department":
            if requested_department_id not in {None, self.department_id}:
                raise PermissionDeniedError("不能访问其他部门的数据")
            return self.department_id
        if requested_department_id is not None:
            raise PermissionDeniedError("当前账号没有部门数据范围")
        return None

    def can_review_inbox(self, principal: Principal) -> bool:
        """未分派记录只对收件或写入角色开放。"""
        return principal.can(INBOX_PERMISSION) or principal.can(WRITE_PERMISSION)

    def authorize_petition(self, principal: Principal, resource_department_id: int | None, *, for_write: bool = False) -> None:
        """按信访件归属放行：

        - 管理员全量可见；
        - 收件（调度）角色可访问任意信访件以便认领、转派、回滚；
        - 未分派记录仅向收件/写入角色开放；
        - 已分派记录必须落在账号自身部门范围内；
        - 无部门的只读账号保留历史全量已分派读取视图（for_write=False）。
        """
        if self.mode == "all":
            return
        if principal.can(INBOX_PERMISSION):
            return
        if resource_department_id is None:
            # 未分派记录：只放行写入角色；只读账号（含无部门账号）一律拒绝
            if principal.can(WRITE_PERMISSION):
                return
            raise PermissionDeniedError(OUT_OF_SCOPE_MESSAGE)
        if self.mode == "department" and resource_department_id == self.department_id:
            return
        # 无部门的只读账号保留历史全量已分派读取视图；写入仍须有明确部门归属
        if self.mode == "self" and not for_write:
            return
        raise PermissionDeniedError(OUT_OF_SCOPE_MESSAGE)

    def require_owned_department(self, resource_department_id: int | None) -> None:
        if self.mode == "all":
            return
        if self.mode == "department" and resource_department_id == self.department_id:
            return
        raise PermissionDeniedError(OUT_OF_SCOPE_MESSAGE)
