# coldchain-gateway — 冷链网关密钥轮换与验签服务

冷链网关换钥时，各实例的阶段分歧会误拒新报文或放过旧钥。本服务以 PostgreSQL 为唯一权威，
集中管理每个租户的 Ed25519 公钥生命周期（当前 / 候选 / 退役中 / 已退休），并对网关报文
验签、开具回执。所有实例读取同一份角色快照，阶段分歧随之消除。

## 架构

- `api`：Python 3.12 + FastAPI，无状态，可水平扩展。
- `db`：PostgreSQL 16，保存租户密钥、持钥证明与验签回执。
- `api2`：第二个 `api` 实例，仅随验收 profile 启动，用于跨实例覆盖过期、重放与竞争。
- `verify`：一次性验收服务，以 pytest 黑盒验收 `api`/`api2` 实例；不占用宿主机端口，退出码即验收结果。

## 密钥状态机

每个租户同一时刻：**当前钥恰一把；候选、退役中各至多一把；已退休不限**。

```
                登记首个公钥          登记第二公钥          promote                retire
∅ ─────────────────────▶ current ──────────────────▶ current ───────────────▶ current(新) ─────────▶ current
                                                      + candidate            + retiring(旧)          (+ retired)
```

- **登记（register）**：租户无钥 → 新钥为当前；仅有当前钥 → 新钥为候选；其余情形 → 409。
- **提升（promote）**：需存在候选且无退役中钥；同一事务内候选 → 当前、旧当前 → 退役中。
- **退休（retire）**：需存在退役中钥；退役中 → 已退休（不可逆）。
- 非法迁移返回 **409**，响应体携带权威角色视图 `roles`，调用方可据此对齐本地状态。

### 并发正确性

- 所有状态迁移在事务内先取 `pg_advisory_xact_lock(hashtext('tenant_keys'), hashtext(tenant))`，
  按租户串行化，迁移在提交前对其他事务不可见。
- 三个部分唯一索引（每租户每在用角色至多一行）作为兜底：任何残余竞态都会退化为
  唯一约束冲突并返回 409。
- 验签以**单次角色读取为排序点**：快照早于退休提交则可验签成功，晚于退休提交则返回
  `KEY_RETIRED`。两种结果都正确，取决于排序点落在哪一侧。

## 提升前持钥证明（可选租户策略）

登记的公钥可能被误录：直接提升会让网关开始用一把设备并不持有的公钥，导致报文中断。
为此增加**租户级、默认关闭**的“提升前持钥证明”（proof-of-possession, PoP）策略。
关闭时登记、提升、验签与本章节之前描述完全一致；启用后提升必须先消费一份一次性证明。

### 流程

1. 管理员 `PUT /v1/tenants/{tenantId}/policy` 开启 `popRequired`（可指定
   `challengeTtlSeconds`，默认 120s）。
2. 管理员对**当前候选钥** `POST .../pop-challenges` 申请一次性随机挑战；服务记录
   租户、candidate keyId、当时的 current keyId 与**当前钥代次**（`key_generation`，
   首次建钥为 0，每次成功提升 +1），返回 `challengeId` 与随机 `nonce`。同一候选钥的
   未决挑战重复申请是幂等的（返回同一挑战）。
3. 网关/设备用**候选私钥**对规范化消息（包含租户、candidate/current keyId、代次、
   challengeId、nonce）做 Ed25519 签名，`POST .../pop-challenges/{challengeId}/answer`
   交回。服务以候选公钥验签通过后，登记一份**限时证明**（状态 `answered`）。
4. 提升在同一租户事务内：取租户锁 → 校验存在**有效、未消费、上下文完全匹配**
   （租户 + candidate + current + 代次）的证明 → 立即置为 `consumed` →
   候选转当前、旧当前转退役中、代次 +1。

放行条件缺一不可：

- **过期**：挑战在应答前过期 → 410 `POP_CHALLENGE_EXPIRED`；证明在提升前过期 →
  410 `POP_PROOF_EXPIRED`（响应附权威 `roles`）。
- **重复提交 / 重放**：同一挑战重复应答 → 409 `POP_PROOF_DUPLICATE`；已消费的证明
  不能再应答（409 `POP_PROOF_CONSUMED`）也不能驱动第二次提升。
- **候选或当前钥变化**：挑战记录的 candidate/current/代次与当下不一致 →
  409 `POP_PROOF_MISMATCH`；签名消息同样绑定这些字段，跨代次签名无法复用。
- **跨租户挪用**：挑战按 `(租户, challengeId)` 定位，别的租户提交统一返回
  404 `POP_CHALLENGE_NOT_FOUND`，与“未知”不可区分。
- 失败路径**不改变任何密钥角色**；策略关闭期间按旧规则提升，之后重新开启策略时，
  旧挑战若上下文已漂移同样被拒。

并发：提升仍由租户咨询锁串行化，证明消费与角色交换在同一事务，故**并发提升只能成功
一次**；失败者得到 200 提交后的权威 `roles`（409 `ILLEGAL_TRANSITION`）。
认证、租户隔离、退役钥拒签（410）、验签回执规则均不改变（坏签名不产生回执）。

> 过期判定使用数据库中的**共享虚拟时钟**（`now()` + `service_clock` 偏移），
> 所有 API 实例看到同一时间。只有在设置 `CLOCK_CONTROL_ENABLED=1` 时才暴露
> 管理接口 `POST /internal/clock/advance|reset`（默认关闭、关闭时 404），
> 仅供确定性验收推进时间。

## API

认证：`Authorization: Bearer <token>`。令牌缺失或无效 → **401**；令牌有效但越权 → **403**。

| 令牌 | 环境变量 | 权限（scope） |
|---|---|---|
| 管理令牌 | `ADMIN_TOKEN` | `keys:manage` + `verify` |
| 网关令牌 | `GATEWAY_TOKEN` | `verify` |

| 方法 | 路径 | 权限 | 说明 |
|---|---|---|---|
| POST | `/v1/tenants/{tenantId}/keys` | `keys:manage` | 登记公钥（201） |
| POST | `/v1/tenants/{tenantId}/keys/promote` | `keys:manage` | 提升候选（200） |
| POST | `/v1/tenants/{tenantId}/keys/retire` | `keys:manage` | 退休退役中钥（200） |
| GET | `/v1/tenants/{tenantId}/keys` | `keys:manage` | 权威角色视图（含已退休列表） |
| GET | `/v1/tenants/{tenantId}/receipts` | `keys:manage` | 回执列表 |
| GET/PUT | `/v1/tenants/{tenantId}/policy` | `keys:manage` | 查看/设置租户 PoP 策略 |
| POST | `/v1/tenants/{tenantId}/pop-challenges` | `keys:manage` | 为当前候选钥申请一次性挑战（201） |
| POST | `/v1/tenants/{tenantId}/pop-challenges/{challengeId}/answer` | `keys:manage` | 提交候选私钥签名，登记限时证明（200） |
| GET | `/v1/tenants/{tenantId}/pop-challenges` | `keys:manage` | 列出挑战/证明状态 |
| POST | `/v1/verify` | `verify` | 验签并开具回执（202） |
| POST | `/internal/clock/advance`、`/internal/clock/reset` | `keys:manage` | **仅验收**：推进/重置共享虚拟时钟（默认 404） |
| GET | `/healthz` | — | 健康检查 |

### 登记公钥

```http
POST /v1/tenants/{tenantId}/keys
Authorization: Bearer <admin-token>
Content-Type: application/json

{"keyId": "k-2026-09", "publicKey": "<32 字节 Ed25519 公钥，无填充 base64url>"}
```

- 201 → `{"keyId", "role": "current" | "candidate", "roles": {...}}`
- 409 → `{"error": "ILLEGAL_TRANSITION" | "KEY_ALREADY_EXISTS", "roles": {...}}`

### 持钥证明

```http
PUT /v1/tenants/{tenantId}/policy
Authorization: Bearer <admin-token>
Content-Type: application/json

{"popRequired": true, "challengeTtlSeconds": 120}
```

```http
POST /v1/tenants/{tenantId}/pop-challenges
Authorization: Bearer <admin-token>

# 201
{"challengeId": "<uuid>", "nonce": "<16 字节 base64url>", "status": "issued",
 "candidateKeyId": "k-2026-09", "currentKeyId": "k-2026-01",
 "currentGeneration": 0, "ttlSeconds": 120,
 "issuedAt": "...", "expiresAt": "..."}
```

候选私钥签名的规范化消息（Ed25519，覆盖完整字符串字节）：

```
coldchain-pop-v1
tenant=<tenantId>
candidate=<candidateKeyId>
current=<currentKeyId>
generation=<currentGeneration>
challenge=<challengeId>
nonce=<base64url-nonce>
```

```http
POST /v1/tenants/{tenantId}/pop-challenges/{challengeId}/answer
Content-Type: application/json

{"signature": "<64 字节无填充 base64url Ed25519 签名>"}
# 200 → 同上结构，status 变为 "answered"
```

随后正常调用提升接口；证明在提升事务内消费，`roles` 之外额外返回
`keyGeneration`。

### 验签

```http
POST /v1/verify
Authorization: Bearer <gateway-token>
X-Tenant-Id: <tenantId>
X-Key-Id: <keyId>
X-Signature: <64 字节 Ed25519 签名，无填充 base64url，覆盖原始请求体字节>

<0 .. 1048576 字节原始报文>
```

- 202 → `{"receiptId": "<uuid>"}`，回执落库（含报文 SHA-256 与大小）。
- 三个在用角色（当前 / 候选 / 退役中）均可验签。

### 错误码

| 状态 | `error` | 含义 |
|---|---|---|
| 400 | `BAD_REQUEST` | 缺少必需的头或字段非法 |
| 400 | `BAD_PUBLIC_KEY` | 公钥不是无填充 base64url 编码的 32 字节 |
| 400 | `BAD_SIGNATURE` | 签名错误或格式非法（**不产生回执**） |
| 401 | `UNAUTHORIZED` | 令牌缺失或无效 |
| 403 | `FORBIDDEN` | 令牌有效但越权 |
| 404 | `KEY_UNKNOWN` | keyId 未知或属于其他租户（两者统一、不可区分） |
| 404 | `POP_CHALLENGE_NOT_FOUND` | challengeId 未知、属于其他租户或非 UUID（统一、不可区分） |
| 409 | `ILLEGAL_TRANSITION` / `KEY_ALREADY_EXISTS` | 非法迁移 / keyId 冲突（附权威 `roles`） |
| 409 | `POP_POLICY_DISABLED` | 租户未开启持钥证明策略时申请/应答挑战 |
| 409 | `POP_PROOF_REQUIRED` | 启用策略但提升时没有有效证明（附权威 `roles`） |
| 409 | `POP_PROOF_DUPLICATE` | 同一挑战重复应答 |
| 409 | `POP_PROOF_CONSUMED` | 证明已被成功提升消费，重放被拒 |
| 409 | `POP_PROOF_MISMATCH` | 证明绑定的候选/当前钥或代次已变化（附权威 `roles`） |
| 410 | `KEY_RETIRED` | 读取快照晚于退休提交 |
| 410 | `POP_CHALLENGE_EXPIRED` / `POP_PROOF_EXPIRED` | 挑战应答前过期 / 证明提升前过期（后者附 `roles`） |
| 413 | `PAYLOAD_TOO_LARGE` | 报文超过 1048576 字节 |

## 快速开始

```bash
# 宿主机端口必须由 API_PORT 指定；compose 不占用任何默认端口，未设置会直接报错。
API_PORT=8080 docker compose up --build -d db api
curl -s http://localhost:8080/healthz

# 一次性验收：对 api/api2 两个实例运行 pytest（含过期、重放、角色变更、竞争），
# 退出码即验收结果；verify profile 会启用 api2 与共享虚拟时钟控制面。
CLOCK_CONTROL_ENABLED=1 API_PORT=8080 \
  docker compose --profile verify up --build --exit-code-from verify verify
```

端到端示例（登记 → 验签 → 轮换 → 退休）：

```bash
AUTH="Authorization: Bearer $ADMIN_TOKEN"
# 生成密钥对（任选工具），公钥以无填充 base64url 编码后登记
curl -X POST "http://localhost:$API_PORT/v1/tenants/t1/keys" \
  -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"keyId": "k1", "publicKey": "<unpadded-base64url-32B>"}'

# 网关验签：签名覆盖原始请求体字节
curl -X POST "http://localhost:$API_PORT/v1/verify" \
  -H "Authorization: Bearer $GATEWAY_TOKEN" \
  -H 'X-Tenant-Id: t1' -H 'X-Key-Id: k1' -H "X-Signature: <unpadded-base64url-64B>" \
  --data-binary '@payload.bin'

# 轮换：登记候选 → 提升 → 退休旧钥
curl -X POST "http://localhost:$API_PORT/v1/tenants/t1/keys" -H "$AUTH" \
  -H 'Content-Type: application/json' -d '{"keyId": "k2", "publicKey": "..."}'
curl -X POST "http://localhost:$API_PORT/v1/tenants/t1/keys/promote" -H "$AUTH"
curl -X POST "http://localhost:$API_PORT/v1/tenants/t1/keys/retire"  -H "$AUTH"
```

## 环境变量

| 变量 | 服务 | 默认 | 说明 |
|---|---|---|---|
| `API_PORT` | `api`（宿主机映射） | 无（必填） | 宿主机端口；不设置则 compose 拒绝启动，避免占位 |
| `DATABASE_URL` | `api` | compose 内置 | PostgreSQL DSN |
| `ADMIN_TOKEN` / `GATEWAY_TOKEN` | `api`, `verify` | `dev-admin-token` / `dev-gateway-token` | 仅为本地默认值，生产必须覆盖 |
| `CLOCK_CONTROL_ENABLED` | `api` | `0`（关闭） | 为 `1` 时暴露 `/internal/clock/*`；仅限验收使用 |
| `API_PORT2` | `api2`（宿主机映射） | `8002` | 第二实例的宿主机端口，仅 `verify` profile 使用 |
| `API_BASE_URL` / `API_BASE2_URL` | `verify` | `http://api:8000` / `http://api:8001` | 被验收的两个实例地址（compose 已分别指向 api2/api） |

## 本地开发

```bash
python3.12 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
export DATABASE_URL=postgresql://coldchain:coldchain@localhost:5432/coldchain
export ADMIN_TOKEN=dev-admin-token GATEWAY_TOKEN=dev-gateway-token
uvicorn app.main:app --reload

# 另开一个终端，对运行中的实例做验收；时间相关用例通过共享虚拟时钟推进
uvicorn app.main:app --port 8001 &  # 第二个实例，覆盖跨实例竞争
API_BASE_URL=http://localhost:8000 API_BASE2_URL=http://localhost:8001 \
CLOCK_CONTROL_ENABLED=1 pytest tests/ -v
```

注：两个实例需同时带 `CLOCK_CONTROL_ENABLED=1` 启动，时钟偏移保存在数据库中，
故两实例共享。
