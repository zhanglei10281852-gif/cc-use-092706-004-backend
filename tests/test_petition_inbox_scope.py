from __future__ import annotations


def _headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _login(client, username: str, password: str) -> str:
    response = client.post("/api/auth/login", json={"username": username, "password": password, "client_label": "tests"})
    assert response.status_code == 200, response.text
    return response.json()["token"]


def _setup_world(client, admin_headers):
    """构造：两个部门 + 值班员(无部门) + 两部门经办员 + 只读账号。"""
    d1 = client.post("/api/departments", headers=admin_headers, json={"name": "水务科", "manager": "李主任", "phone": "010-11110000"})
    d2 = client.post("/api/departments", headers=admin_headers, json={"name": "执法科", "manager": "王主任", "phone": "010-22220000"})
    assert d1.status_code == 201 and d2.status_code == 201
    dept1, dept2 = d1.json()["id"], d2.json()["id"]

    role = client.post(
        "/api/roles",
        headers=admin_headers,
        json={"code": "petition.handler", "name": "信访经办", "permission_codes": ["petitions.read", "petitions.write"]},
    )
    assert role.status_code == 201, role.text
    reader = client.post(
        "/api/roles",
        headers=admin_headers,
        json={"code": "petition.reader", "name": "信访只读", "permission_codes": ["petitions.read"]},
    )
    assert reader.status_code == 201, reader.text

    users = [
        ("duty.user", "Duty!123456", "值班员", None, ["duty"]),
        ("dept1.user", "Deal!123456", "水务经办", dept1, ["petition.handler"]),
        ("dept2.user", "Deal!123456", "执法经办", dept2, ["petition.handler"]),
        ("read.user", "Read!123456", "只读账号", None, ["petition.reader"]),
    ]
    for username, password, display, department, roles in users:
        payload = {"username": username, "password": password, "display_name": display, "role_codes": roles}
        if department is not None:
            payload["department_id"] = department
        created = client.post("/api/users", headers=admin_headers, json=payload)
        assert created.status_code == 201, created.text

    return {
        "dept1_id": dept1,
        "dept2_id": dept2,
        "duty": _headers(_login(client, "duty.user", "Duty!123456")),
        "dept1": _headers(_login(client, "dept1.user", "Deal!123456")),
        "dept2": _headers(_login(client, "dept2.user", "Deal!123456")),
        "reader": _headers(_login(client, "read.user", "Read!123456")),
    }


def _create_petition(client, target: str = "湿地边界争议") -> int:
    response = client.post("/petitions", json={"type": "投诉举报", "target": target, "content": "公众上报线索", "contact": "13800000000"})
    assert response.status_code == 201, response.text
    return response.json()["id"]


def _transition(client, headers, petition_id, target_status, **extra):
    payload = {"target_status": target_status, **extra}
    return client.post(f"/api/petition-workflow/{petition_id}/transition", headers=headers, json=payload)


def _denied_audit_count(client, admin_headers, petition_id) -> int:
    response = client.get(
        "/api/audit?resource_type=petition&outcome=denied",
        headers=admin_headers,
    )
    assert response.status_code == 200, response.text
    return sum(1 for event in response.json()["data"] if event["resource_id"] == str(petition_id))


def test_claim_then_scope_tightens_and_urge(client, admin):
    admin_headers = admin["headers"]
    world = _setup_world(client, admin_headers)
    petition_id = _create_petition(client)

    # 未分派收件箱：值班员与具备写权限的部门经办员可见；纯只读账号不可见。
    inbox = client.get("/api/petition-workflow?status=待签收", headers=world["duty"])
    assert inbox.status_code == 200
    assert any(row["id"] == petition_id for row in inbox.json()["data"])
    inbox_clerk = client.get("/api/petition-workflow", headers=world["dept1"])
    assert any(row["id"] == petition_id and row["department_id"] is None for row in inbox_clerk.json()["data"])
    assert client.get(f"/api/petition-workflow/{petition_id}", headers=world["reader"]).status_code == 403

    # 值班员签收 → 待分派（认领前置）。
    signed = _transition(client, world["duty"], petition_id, "待分派")
    assert signed.status_code == 200, signed.text
    assert signed.json()["status"] == "待分派"

    # 认领分派到水务科：认领后立即按部门范围收紧。
    claimed = _transition(client, world["duty"], petition_id, "办理中", department_id=world["dept1_id"])
    assert claimed.status_code == 200, claimed.text
    body = claimed.json()
    assert body["status"] == "办理中" and body["department_id"] == world["dept1_id"]

    # 值班员（无部门）与执法科立刻失去访问；水务科可见。
    assert client.get(f"/api/petition-workflow/{petition_id}", headers=world["duty"]).status_code == 403
    assert client.get(f"/api/petition-workflow/{petition_id}", headers=world["dept2"]).status_code == 403
    detail = client.get(f"/api/petition-workflow/{petition_id}", headers=world["dept1"])
    assert detail.status_code == 200 and detail.json()["department_id"] == world["dept1_id"]

    # 列表同样收紧：值班员收件箱不再含此件，水务科列表含此件。
    duty_rows = client.get("/api/petition-workflow", headers=world["duty"]).json()["data"]
    assert all(row["id"] != petition_id for row in duty_rows)
    dept1_rows = client.get("/api/petition-workflow", headers=world["dept1"]).json()["data"]
    assert any(row["id"] == petition_id for row in dept1_rows)

    # 催办：承办部门可催办，其他部门越权催办返回原 403 且写入 denied 审计。
    urge_ok = client.post(f"/api/petition-workflow/{petition_id}/urge", headers=world["dept1"], json={"reason": "请尽快处理"})
    assert urge_ok.status_code == 201, urge_ok.text
    urge_denied = client.post(f"/api/petition-workflow/{petition_id}/urge", headers=world["dept2"], json={"reason": "越权催办"})
    assert urge_denied.status_code == 403
    assert urge_denied.json()["error"]["code"] == "permission_denied"
    assert _denied_audit_count(client, admin_headers, petition_id) >= 1

    # 越权访问没有产生任何催办记录。
    detail = client.get(f"/api/petition-workflow/{petition_id}", headers=world["dept1"]).json()
    assert len(detail["urge_records"]) == 1


def test_transfer_between_departments(client, admin):
    admin_headers = admin["headers"]
    world = _setup_world(client, admin_headers)
    petition_id = _create_petition(client)
    _transition(client, world["duty"], petition_id, "待分派")
    _transition(client, world["duty"], petition_id, "办理中", department_id=world["dept1_id"])

    # 转派由具备收件权限的值班员执行：水务科 → 执法科。
    transferred = _transition(client, world["duty"], petition_id, "办理中", department_id=world["dept2_id"])
    assert transferred.status_code == 200, transferred.text
    assert transferred.json()["department_id"] == world["dept2_id"]

    # 转派后访问权即时切换。
    assert client.get(f"/api/petition-workflow/{petition_id}", headers=world["dept1"]).status_code == 403
    assert client.get(f"/api/petition-workflow/{petition_id}", headers=world["dept2"]).status_code == 200
    urge = client.post(f"/api/petition-workflow/{petition_id}/urge", headers=world["dept2"], json={"reason": "转派后催办"})
    assert urge.status_code == 201

    # 转派到不存在/停用部门仍报错。
    bad = _transition(client, world["duty"], petition_id, "办理中", department_id=99999)
    assert bad.status_code == 404

    # 流转记录包含转派动作。
    detail = client.get(f"/api/petition-workflow/{petition_id}", headers=world["dept2"]).json()
    assert "转派承办部门" in [row["action"] for row in detail["flow_records"]]


def test_rollback_claim_returns_to_inbox(client, admin):
    admin_headers = admin["headers"]
    world = _setup_world(client, admin_headers)
    petition_id = _create_petition(client)
    _transition(client, world["duty"], petition_id, "待分派")
    _transition(client, world["duty"], petition_id, "办理中", department_id=world["dept1_id"])

    # 回滚认领：办理中 → 待分派，解除部门归属并作废时限。
    rolled = _transition(client, world["duty"], petition_id, "待分派")
    assert rolled.status_code == 200, rolled.text
    body = rolled.json()
    assert body["status"] == "待分派" and body["department_id"] is None and body["deadline"] is None

    # 记录回到未分派收件箱：值班员可见，原承办部门也仍可在收件箱看到（具备写权限），
    # 但部门归属解除后，承办部门不能再按本部门记录催办。
    assert client.get(f"/api/petition-workflow/{petition_id}", headers=world["duty"]).status_code == 200
    assert client.get(f"/api/petition-workflow/{petition_id}", headers=world["dept1"]).status_code == 200
    urge_after_rollback = client.post(f"/api/petition-workflow/{petition_id}/urge", headers=world["dept1"], json={"reason": "回滚后催办"})
    assert urge_after_rollback.status_code == 403
    # 执法科（非认领部门）同样只能以收件箱视角看到，不能办理。
    assert client.post(f"/api/petition-workflow/{petition_id}/urge", headers=world["dept2"], json={"reason": "越权催办"}).status_code == 403
    inbox_rows = client.get("/api/petition-workflow?status=待分派", headers=world["duty"]).json()["data"]
    assert any(row["id"] == petition_id and row["department_id"] is None for row in inbox_rows)
    detail = client.get(f"/api/petition-workflow/{petition_id}", headers=world["duty"]).json()
    assert any("回退收件箱" in row["action"] for row in detail["flow_records"])

    # 可重新认领。
    reclaimed = _transition(client, world["duty"], petition_id, "办理中", department_id=world["dept2_id"])
    assert reclaimed.status_code == 200
    assert reclaimed.json()["department_id"] == world["dept2_id"]


def test_admin_full_view_and_historical_records_unchanged(client, admin):
    admin_headers = admin["headers"]
    world = _setup_world(client, admin_headers)
    p_unassigned = _create_petition(client, "未分派线索")
    p_assigned = _create_petition(client, "历史已分派线索")
    _transition(client, world["duty"], p_assigned, "待分派")
    _transition(client, world["duty"], p_assigned, "办理中", department_id=world["dept2_id"])

    # 管理员始终可见全量（含未分派与各部门记录），可按部门筛选。
    all_rows = client.get("/api/petition-workflow", headers=admin_headers).json()["data"]
    ids = {row["id"] for row in all_rows}
    assert {p_unassigned, p_assigned} <= ids
    filtered = client.get(f"/api/petition-workflow?department_id={world['dept2_id']}", headers=admin_headers)
    assert filtered.status_code == 200
    assert all(row["department_id"] == world["dept2_id"] for row in filtered.json()["data"])
    assert any(row["id"] == p_assigned for row in filtered.json()["data"])

    # 历史已分派记录维持部门边界：执法科可见，水务科不可见。
    assert client.get(f"/api/petition-workflow/{p_assigned}", headers=world["dept2"]).status_code == 200
    assert client.get(f"/api/petition-workflow/{p_assigned}", headers=world["dept1"]).status_code == 403

    # 无权限账号访问列表仍被拒绝。
    assert client.get("/api/petition-workflow", headers=world["reader"]).status_code == 200  # 只读：空范围
    assert all(row["id"] not in {p_unassigned, p_assigned} for row in client.get("/api/petition-workflow", headers=world["reader"]).json()["data"])


def test_denied_access_is_audited_and_rolls_back(client, admin):
    admin_headers = admin["headers"]
    world = _setup_world(client, admin_headers)
    petition_id = _create_petition(client)

    # 未分派件：纯只读账号不能执行收件箱流转（缺少收件/写权限）。
    denied = _transition(client, world["reader"], petition_id, "待分派")
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "permission_denied"
    assert client.get(f"/api/petition-workflow/{petition_id}", headers=world["reader"]).status_code == 403

    denied_events = client.get(
        "/api/audit?resource_type=petition&outcome=denied",
        headers=admin_headers,
    ).json()["data"]
    actions = {event["action"] for event in denied_events}
    assert {"petition.transition.denied", "petition.access.denied"} <= actions
    assert all(event["resource_id"] == str(petition_id) for event in denied_events)

    # 原始记录状态未被越权尝试改动。
    admin_view = client.get(f"/api/petition-workflow/{petition_id}", headers=admin_headers).json()
    assert admin_view["status"] == "待签收" and admin_view["department_id"] is None
