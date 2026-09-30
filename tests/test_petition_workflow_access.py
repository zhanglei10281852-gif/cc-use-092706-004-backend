from __future__ import annotations


def _headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _make_department(client, admin, name: str) -> int:
    response = client.post(
        "/api/departments",
        headers=admin["headers"],
        json={"name": name, "manager": f"{name}负责人", "phone": "0571-88000000"},
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def _make_role(client, admin, code: str, permission_codes: list[str]) -> None:
    response = client.post(
        "/api/roles",
        headers=admin["headers"],
        json={"code": code, "name": code, "permission_codes": permission_codes},
    )
    assert response.status_code == 201, response.text


def _login(client, username: str, password: str) -> str:
    response = client.post("/api/auth/login", json={"username": username, "password": password, "client_label": "tests"})
    assert response.status_code == 200, response.text
    return response.json()["token"]


def _make_user(client, admin, username: str, role: str, department_id: int | None) -> str:
    password = "Claim!23456"
    response = client.post(
        "/api/users",
        headers=admin["headers"],
        json={
            "username": username,
            "password": password,
            "display_name": username,
            "department_id": department_id,
            "role_codes": [role],
        },
    )
    assert response.status_code == 201, response.text
    return _login(client, username, password)


def _new_petition_in_inbox(client, admin_headers: dict) -> int:
    """经 legacy 提交接口建档，再由管理员签收进入未分派收件箱。"""
    created = client.post(
        "/petitions",
        json={"type": "投诉举报", "target": "湿地排污", "content": "夜间疑似偷排", "contact": "13800000000"},
    )
    assert created.status_code == 201, created.text
    petition_id = created.json()["id"]
    received = client.post(
        f"/api/petition-workflow/{petition_id}/transition",
        headers=admin_headers,
        json={"target_status": "待分派"},
    )
    assert received.status_code == 200, received.text
    return petition_id


def _setup_world(client, admin):
    dept_a = _make_department(client, admin, "湿地管护一科")
    dept_b = _make_department(client, admin, "湿地管护二科")
    _make_role(client, admin, "inbox.dispatcher", ["petitions.read", "petitions.inbox"])
    _make_role(client, admin, "dept.handler", ["petitions.read", "petitions.write"])
    _make_role(client, admin, "petition.reader", ["petitions.read"])
    dispatcher = _make_user(client, admin, "dispatcher", "inbox.dispatcher", None)
    handler_a = _make_user(client, admin, "handler.a", "dept.handler", dept_a)
    handler_b = _make_user(client, admin, "handler.b", "dept.handler", dept_b)
    reader = _make_user(client, admin, "plain.reader", "petition.reader", None)
    return {
        "dept_a": dept_a,
        "dept_b": dept_b,
        "dispatcher": _headers(dispatcher),
        "handler_a": _headers(handler_a),
        "handler_b": _headers(handler_b),
        "reader": _headers(reader),
    }


def test_inbox_visible_only_to_inbox_or_write_roles(client, admin):
    world = _setup_world(client, admin)
    petition_id = _new_petition_in_inbox(client, admin["headers"])

    # 值班调度角色可看收件箱
    inbox = client.get("/api/petition-workflow?inbox=true", headers=world["dispatcher"])
    assert inbox.status_code == 200
    assert any(item["id"] == petition_id and item["department_id"] is None for item in inbox.json()["data"])

    # 有写入权限的部门经办同样可见未分派记录
    inbox_writer = client.get("/api/petition-workflow?inbox=true", headers=world["handler_a"])
    assert inbox_writer.status_code == 200
    assert any(item["id"] == petition_id for item in inbox_writer.json()["data"])

    # 普通只读账号：收件箱一律拒绝
    denied = client.get("/api/petition-workflow?inbox=true", headers=world["reader"])
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "permission_denied"

    # 普通列表也不暴露未分派记录
    normal = client.get("/api/petition-workflow", headers=world["reader"])
    assert normal.status_code == 200
    assert all(item["department_id"] is not None for item in normal.json()["data"])

    # 未分派件详情对只读账号不可见
    detail = client.get(f"/api/petition-workflow/{petition_id}", headers=world["reader"])
    assert detail.status_code == 403


def test_claim_tightens_scope_and_urge_audits_denial(client, admin):
    world = _setup_world(client, admin)
    petition_id = _new_petition_in_inbox(client, admin["headers"])

    # 一科经办认领到一科
    claimed = client.post(
        f"/api/petition-workflow/{petition_id}/transition",
        headers=world["handler_a"],
        json={"target_status": "办理中", "department_id": world["dept_a"]},
    )
    assert claimed.status_code == 200, claimed.text
    body = claimed.json()
    assert body["status"] == "办理中"
    assert body["department_id"] == world["dept_a"]

    # 认领后立即按部门收紧：二科看不到、催办被拒
    assert client.get(f"/api/petition-workflow/{petition_id}", headers=world["handler_b"]).status_code == 403
    urge_denied = client.post(
        f"/api/petition-workflow/{petition_id}/urge",
        headers=world["handler_b"],
        json={"reason": "请尽快处理"},
    )
    assert urge_denied.status_code == 403

    # 只读账号对已分派历史记录仍可读，但不能催办
    assert client.get(f"/api/petition-workflow/{petition_id}", headers=world["reader"]).status_code == 200
    reader_urge = client.post(
        f"/api/petition-workflow/{petition_id}/urge",
        headers=world["reader"],
        json={"reason": "请尽快处理"},
    )
    assert reader_urge.status_code == 403

    # 本科室催办成功
    urge_ok = client.post(
        f"/api/petition-workflow/{petition_id}/urge",
        headers=world["handler_a"],
        json={"reason": "临期提醒"},
    )
    assert urge_ok.status_code == 201
    assert urge_ok.json()["reason"] == "临期提醒"

    # 越权访问写入 denied 审计
    audit = client.get("/api/audit?action=petition.urge&outcome=denied", headers=admin["headers"])
    assert audit.status_code == 200
    rows = audit.json()["data"]
    assert any(row["resource_id"] == str(petition_id) for row in rows)


def test_cannot_claim_unassigned_into_other_department(client, admin):
    world = _setup_world(client, admin)
    petition_id = _new_petition_in_inbox(client, admin["headers"])

    # 二科经办只能认领到二科；尝试指定一科被拒
    response = client.post(
        f"/api/petition-workflow/{petition_id}/transition",
        headers=world["handler_b"],
        json={"target_status": "办理中", "department_id": world["dept_a"]},
    )
    assert response.status_code == 403
    # 记录仍停留在未分派收件箱
    detail = client.get(f"/api/petition-workflow/{petition_id}", headers=world["dispatcher"])
    assert detail.json()["status"] == "待分派"
    assert detail.json()["department_id"] is None


def test_reassign_moves_scope_between_departments(client, admin):
    world = _setup_world(client, admin)
    petition_id = _new_petition_in_inbox(client, admin["headers"])
    client.post(
        f"/api/petition-workflow/{petition_id}/transition",
        headers=world["handler_a"],
        json={"target_status": "办理中", "department_id": world["dept_a"]},
    )

    # 普通部门经办无权转派
    forbidden = client.post(
        f"/api/petition-workflow/{petition_id}/reassign",
        headers=world["handler_a"],
        json={"department_id": world["dept_b"], "reason": "职责调整"},
    )
    assert forbidden.status_code == 403

    # 调度角色转派一科 -> 二科
    moved = client.post(
        f"/api/petition-workflow/{petition_id}/reassign",
        headers=world["dispatcher"],
        json={"department_id": world["dept_b"], "reason": "职责调整"},
    )
    assert moved.status_code == 200, moved.text
    assert moved.json()["department_id"] == world["dept_b"]

    # 范围随转派立即收紧：一科失权，二科可催办
    assert client.get(f"/api/petition-workflow/{petition_id}", headers=world["handler_a"]).status_code == 403
    assert client.get(f"/api/petition-workflow/{petition_id}", headers=world["handler_b"]).status_code == 200
    urge = client.post(
        f"/api/petition-workflow/{petition_id}/urge",
        headers=world["handler_b"],
        json={"reason": "转派后跟进"},
    )
    assert urge.status_code == 201

    audit = client.get("/api/audit?action=petition.reassign", headers=admin["headers"])
    assert any(row["resource_id"] == str(petition_id) and row["outcome"] == "success" for row in audit.json()["data"])


def test_rollback_returns_record_to_inbox(client, admin):
    world = _setup_world(client, admin)
    petition_id = _new_petition_in_inbox(client, admin["headers"])
    client.post(
        f"/api/petition-workflow/{petition_id}/transition",
        headers=world["handler_a"],
        json={"target_status": "办理中", "department_id": world["dept_a"]},
    )

    # 调度角色回滚认领：记录退回待分派，清除部门与时限
    rolled = client.post(
        f"/api/petition-workflow/{petition_id}/rollback",
        headers=world["dispatcher"],
        json={"reason": "分派有误"},
    )
    assert rolled.status_code == 200, rolled.text
    assert rolled.json()["status"] == "待分派"
    assert rolled.json()["department_id"] is None
    assert rolled.json()["deadline"] is None

    # 回到收件箱：写入角色仍可见未分派件，但已脱离办理中、不能再催办
    assert client.get(f"/api/petition-workflow/{petition_id}", headers=world["handler_a"]).status_code == 200
    assert client.get(f"/api/petition-workflow/{petition_id}", headers=world["reader"]).status_code == 403
    urge_after = client.post(
        f"/api/petition-workflow/{petition_id}/urge",
        headers=world["handler_a"],
        json={"reason": "还能催吗"},
    )
    assert urge_after.status_code == 409
    inbox = client.get("/api/petition-workflow?inbox=true&status=待分派", headers=world["dispatcher"])
    assert any(item["id"] == petition_id for item in inbox.json()["data"])

    # 可重新认领
    reclaim = client.post(
        f"/api/petition-workflow/{petition_id}/transition",
        headers=world["handler_b"],
        json={"target_status": "办理中", "department_id": world["dept_b"]},
    )
    assert reclaim.status_code == 200
    assert reclaim.json()["department_id"] == world["dept_b"]

    audit = client.get("/api/audit?action=petition.rollback", headers=admin["headers"])
    assert any(row["resource_id"] == str(petition_id) for row in audit.json()["data"])


def test_admin_full_view_and_history_unchanged(client, admin):
    world = _setup_world(client, admin)
    unassigned = _new_petition_in_inbox(client, admin["headers"])
    assigned = _new_petition_in_inbox(client, admin["headers"])
    client.post(
        f"/api/petition-workflow/{assigned}/transition",
        headers=world["handler_a"],
        json={"target_status": "办理中", "department_id": world["dept_a"]},
    )

    # 管理员全量视图：未分派 + 已分派均可见
    listing = client.get("/api/petition-workflow", headers=admin["headers"])
    ids = {item["id"] for item in listing.json()["data"]}
    assert {unassigned, assigned} <= ids

    assert client.get(f"/api/petition-workflow/{unassigned}", headers=admin["headers"]).status_code == 200
    assert client.get(f"/api/petition-workflow/{assigned}", headers=admin["headers"]).status_code == 200
