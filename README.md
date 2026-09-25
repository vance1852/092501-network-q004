# 城市地下管网安全监测与应急调度服务

本项目为城市供水、排水和燃气管网提供离线后台服务，保存管段、传感器台账、校准证书、传感器读数、泄漏告警、巡检工单、维修审批和应急资源分配。系统使用确定性的风险评分帮助值班人员优先处理高风险管段，账号按角色授予读取、处置和审批权限，状态变化写入 SQLite 审计表。

## 校准证书与设备台账

压力读数只有在传感器已登记入台账、且采样时刻持有有效校准证书时才会被接收：

- 传感器通过 `POST /segments/{id}/sensors` 登记到所属管段；读数上报时校验传感器已登记且挂载在该管段上。
- 证书通过 `POST /sensors/{id}/certificates` 签发，记录有效区间 `valid_from`/`valid_to`（闭区间，端点时刻仍有效）、量程 `range_min`/`range_max`（闭区间）、签发者 `issuer` 和严格递增的 `version`；每份证书带内容指纹 `record_hash`，证书表由触发器保护，只能追加、不能修改或删除。
- 读数按采样时刻 `observed_at` 解析当时有效的最高版本证书，压力值必须在证书量程内；读数行冻结所引用的 `certificate_id` 与 `certificate_version`，事后补发新证书不会改写历史采样引用的版本。
- 撤销由管理员执行（`POST /certificates/{id}/revocation`），撤销记录只追加；自 `revoked_at` 整时刻起该证书不再能接收新读数，历史读数保留并进入质量追溯。
- 重复登记均得到确定结果：相同内容的传感器/证书/撤销重复提交返回 `duplicate: true`，证号或版本号冲突则明确拒绝。
- 质量角色可查询受影响的管段与读数（`GET /quality/affected-segments`、`GET /quality/affected-readings?segment_id=`），风险报告为每条告警标注触发读数的校准状态（`valid`/`expired`/`revoked`）。

## 目录

- `src/urban_network/`：管网领域服务、风险计算、权限、SQLite 存储和 JSON API；
- `src/power_dispatch/`：应急泵站资源分配使用的计划与容量计算组件；
- `src/plant_science/`：传感器校准与统计分析组件；
- `tests/`：领域规则、存储事务和 API 测试。

## 环境

- Linux
- Python 3.11 或更高版本
- 运行时仅使用 Python 标准库和 SQLite

## 测试

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -q
```

## 构建检查

```bash
python3 -m compileall -q src tests
```

## 离线验收

```bash
PYTHONPATH=src python3 -m urban_network.acceptance --workspace .
```

验收命令会创建演示管段、导入传感器读数、计算泄漏风险、生成巡检工单并输出 JSON。它不访问外部网络，也不要求常驻的数据库、队列或其他服务。

## HTTP API

```bash
PYTHONPATH=src python3 -m urban_network.api --database network.sqlite3 --host 127.0.0.1 --port 8080
```

`GET /health` 返回服务状态，其余接口使用 JSON 和 `Authorization: Bearer <token>` 会话，支持管段登记、读数上报、风险查询、工单创建和应急资源分配。
