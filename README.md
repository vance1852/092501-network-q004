# 城市地下管网安全监测与应急调度服务

本项目为城市供水、排水和燃气管网提供离线后台服务，保存管段、传感器读数、泄漏告警、巡检工单、维修审批和应急资源分配。系统使用确定性的风险评分帮助值班人员优先处理高风险管段，账号按角色授予读取、处置和审批权限，状态变化写入 SQLite 审计表。

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

## 校准证书台账

每台传感器的校准证书必须先登记再用于生产读数，证书记录有效区间、压力量程、签发者和按传感器单调递增的版本：

- `POST /certificates`（admin）：登记证书；同一证书 ID 重复提交相同内容返回 `duplicate: true`，内容冲突被拒绝，补发新证书自动获得下一版本号；
- `POST /certificates/{id}/revoke`（admin）：撤销证书，需填写原因，重复撤销返回确定的幂等结果；
- `GET /sensors/{sensor_id}/certificates`：查询证书版本链。

证书内容在数据库层不可变（触发器拒绝改写区间、量程、签发者、版本；被读数引用的证书不可删除），撤销只改变状态。有效区间为半开 `[valid_from, valid_to)`，撤销自撤销时刻起生效，边界时刻归属唯一。

`POST /segments/{id}/readings` 上报读数时必须携带 `certificate_id`：接收流程在同一事务内按**采样时刻**校验证书存在、归属该传感器、状态有效（未撤销且未过期）且压力落在量程内，任一不满足读数即被拒收；通过后读数行固化所引用的证书 ID 与版本快照，事后补发或撤销都不会改写历史读数当时引用的版本。

质量人员可通过 `GET /quality/affected?segment_id=&sensor_id=` 追溯证书事后撤销或过期影响到的管段、读数（含是否触发告警），风险报告 `GET /segments/{id}/risk` 也为每条读数和告警标注采样当时与当前的校准状态。

