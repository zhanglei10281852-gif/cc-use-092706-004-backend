from __future__ import annotations

from dataclasses import dataclass

from app.core.errors import PermissionDeniedError
from app.core.security import Principal


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

    def can_access_petition(self, petition: dict, *, inbox_permission: str | None = None) -> bool:
        """判断当前数据范围能否访问某条信访记录。

        - 管理员（all）：全量视图，始终可见；
        - 已分派记录（department_id 非空）：仅承办部门可见；
        - 未分派记录（收件箱）：仅在拥有收件/写权限（inbox_permission）时可见，
          无部门的值班账号与有部门的部门账号一视同仁，认领后立刻按部门收紧。
        """
        if self.mode == "all":
            return True
        resource_department_id = petition.get("department_id")
        if resource_department_id is not None:
            return self.mode == "department" and resource_department_id == self.department_id
        return inbox_permission is not None

    def require_owned_department(self, resource_department_id: int | None) -> None:
        if self.mode == "all":
            return
        if self.mode == "department" and resource_department_id == self.department_id:
            return
        raise PermissionDeniedError("该业务记录不在当前账号的数据范围内")
