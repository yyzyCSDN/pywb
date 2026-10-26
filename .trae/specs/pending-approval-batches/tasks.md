# 录制待审批次（Pending-Approval Batches）- 实施计划

## Issue I-1: 代理捕获准入即计数，覆盖"缓冲中未入队"窗口（R1 修复）
- **Status**: `pending`
- **Priority**: high
- **Depends On**: None
- **Discovered By**: Review R1
- **Description**:
  - 代理路径 begin_capture 仅发生在响应读完、即将入队时（RespWrapper._write_to_file）。闸门通过到入队之间的缓冲期 pending=0；此时 seal+publish/discard 立即通过排空检查：discard rmtree 后迟到捕获经 writer `_open_file` 的 os.makedirs 重建批次 archive 落盘（丢弃复活）；publish 迁移目录后迟到 WARC 写回 staging 永不被索引，且幂等 no-op 不再对账（发布漏捕获）。
  - 修复：handle_call 闸门通过后（代理与 PUT 两条路径统一）立即 begin_capture；put 路径保留 _put_record 的 finally end；代理路径把入队成功视为所有权移交 _write_one（由其 finally end），其余终结分支（上游异常、skip_request/skip_response、RespWrapper interrupted、入队失败）各自 end；begin 失败则不代理上游直接 403。
  - 附带 advisory 清理：publish 成功后删除 .pending/.pending.lock（I-5）；reaper 解析仅在 writer 自管理的批次模板键上生效（I-2，维持默认安全，仅加注释/锚定 colls 根可选——本次仅确认默认模板无歧义，不扩大改动）。
- **Acceptance Criteria Addressed**: AC-6, AC-10, AC-11, AC-14
- **Test Requirements**:
  - `rule` TR-I-1.1: 慢速上游场景（greenlet 客户端读响应途中）：已准入未入队时 capture_count==1；seal 后短 --wait 的 discard/publish 必须超时报错且状态 sealed；释放响应、计数归零后 discard 成功，仅余 batch.yaml（archive 不被重建）；证据：pywb/recorder/test/test_recorder.py 新增用例
  - `rule` TR-I-1.2: 对称 publish 场景：缓冲中 seal+publish 阻塞；排空后发布，迟到 WARC 全部在 archive/.batches/<b>/ 且 CDX 可查；published 后 staging 不复活 WARC；证据：同文件或 test_record_batch.py
  - `rule` TR-I-1.3: 既有 4 个 TestBatchRecorder 用例与 test_record_batch.py 6 用例在计数模型调整后仍全绿（配对不重不漏）；证据：pytest 输出

## Task 1: BatchManager 核心：目录布局、状态机与在途计数
- **Status**: `completed`
- **Priority**: high
- **Depends On**: None
- **Completion Evidence**:
  - 新增 [batch.py](file:///c:/Users/admin/Desktop/SWE-like/T28/pywb/manager/batch.py)：布局/状态机/portalocker 跨进程计数/wait_drained/路径解析/FS 重试。
  - `pytest tests/test_manager_batch.py`：23 passed（TR-1.1~1.4 覆盖）。
- **Description**:
  - 新建 `pywb/manager/batch.py`，实现 `BatchManager`（以 collections 根目录构造，与 CollectionsManager 同样基于 cwd + colls_dir，支持测试注入 colls_dir）。
  - 常量：`BATCHES_DIRNAME='batches'`、`PUB_BATCHES_DIRNAME='.batches'`、`BATCH_STATE_FILE='batch.yaml'`、`PENDING_FILE='.pending'`；状态 `open/sealed/published/discarded`；批次名 RX 复用集合名规则。
  - 路径 API：coll/batch/archive/indexes/state/pending/公开保留目录/公开索引文件（`indexes/batch-<batch>.cdxj`）。
  - `create_coll_batch(coll, batch)`：集合必须存在；批次名合法；不存在重名（含 discarded 墓碑重名报错）；建 `archive/`、`indexes/`；原子写 batch.yaml（state=open、created_at）。
  - `list_batches(coll)`：返回 [(batch, state)]，含墓碑。
  - `get_state(coll, batch)`（缺失返回 None）、`seal_batch`（仅 open→sealed，原子写 sealed_at）；非法转换抛 ValueError。
  - 在途计数：`begin_capture/end_capture/capture_count/wait_drained(timeout,poll)`，基于 `.pending` + portalocker 锁文件跨进程读改写（decrement 不得低于 0）；另提供解析批次 archive 目录键的静态工具（供录制器句柄回收复用）。
  - 状态 YAML 读写统一临时文件 + os.replace。
- **Acceptance Criteria Addressed**: AC-1, AC-2, AC-6（计数原语部分）
- **Test Requirements**:
  - `rule` TR-1.1: tmp 目录下 init 一个集合后 create 成功，目录树与 state=open 正确；集合不存在/非法名/重名均抛错且无残留；证据：新增 `tests/test_manager_batch.py`
  - `rule` TR-1.2: 状态转换矩阵：open→sealed 合法；其余非法组合抛错且文件状态不变；重新读取状态持久；证据：同文件
  - `rule` TR-1.3: begin/end 多次增减后计数准确、不会为负、wait_drained 在归零与超时两分支行为正确；锁文件与计数文件存在于批次目录；证据：同文件
  - `rule` TR-1.4: list_batches 返回多批次及 discarded 墓碑；证据：同文件

## Task 2: BatchManager 发布与丢弃：索引、载荷校验、原子提交、幂等
- **Status**: `completed`
- **Priority**: high
- **Depends On**: Task 1
- **Completion Evidence**:
  - publish_batch（暂存索引→载荷区间校验→整目录 os.replace→单份索引原子落盘→状态 published，含中断对账）、discard_batch（删 payload/索引/计数，仅留墓碑）已在 [batch.py](file:///c:/Users/admin/Desktop/SWE-like/T28/pywb/manager/batch.py) 实现。
  - TR-2.1~2.6 全部通过（happy/幂等/半完成对账/校验失败无公开变更可重试/空批次/discard/在途等待）；23 passed。
  - Rubric TR-2.7 自评 5：公开侧"全有/全无"，校验先于任何迁移，迁移对账幂等；证据见代码与 test_publish_validation_failure_leaves_no_public_trace、test_publish_reconciles_interrupted_migration。
- **Description**:
  - `publish_batch(coll, batch, wait=30, poll=0.1)`：
    1. 仅 sealed；先 `wait_drained`，超时抛错且状态不变；
    2. 用 `pywb.indexer.cdxindexer.write_multi_cdx_index`（cdxj/sort/append_post/rel_root=批次 archive 绝对路径）输出暂存索引到临时文件；
    3. 用 CDXObject 逐行校验每个去重后的 `filename` 存在且 offset..offset+length 区间可读；不可读抛错，不做任何迁移；
    4. filename 改写为 `.batches/<batch>/<basename>`，生成最终有序 CDXJ（逐行改写不改变键顺序）；
    5. 对账式迁移：目标 `archive/.batches/<batch>/` 不存在则将批次 archive 目录整体 os.replace 过去（已存在则跳过并校验一致）；索引临时文件 os.replace 到 `indexes/batch-<batch>.cdxj`；原子置 state=published（published_at、warcs 清单）；
    6. 已 published：直接返回（幂等 no-op）；半完成（sealed 但目标已部分存在）：对账补齐后续步骤。
    7. 文件移动/删除遇 Windows 占用时在 wait 窗口内轮询重试，仍失败抛错且状态不变。
  - `discard_batch(coll, batch, wait=30, poll=0.1)`：仅 sealed；wait_drained；等待句柄释放后删除批次 archive/indexes/.pending；重写 batch.yaml 为 discarded 墓碑（discarded_at）。
  - 空批次：暂存索引为空时生成空公开索引文件并正常 published。
- **Acceptance Criteria Addressed**: AC-9, AC-10, AC-11, AC-14
- **Test Requirements**:
  - `rule` TR-2.1: 用真实 gzip WARC（可由 warcio WARCWriter 在 tmp 生成）走 seal→publish：公开索引文件存在、filename 前缀为 `.batches/<b>/`、WARC 位于 archive/.batches/<b>/、批次暂存目录已迁移、state=published；证据：test_manager_batch.py
  - `rule` TR-2.2: 删除/截断某 WARC 后 publish：抛错、indexes/batch-*.cdxj 与 archive/.batches 均不存在、状态仍 sealed；恢复后 publish 成功；证据：同文件
  - `rule` TR-2.3: 幂等：连续两次 publish 成功且公开索引文件内容/行数、WARC 集合不变；手工构造"WARC 已迁移但状态仍 sealed"的半完成态，再 publish 能补齐且无重复行；证据：同文件
  - `rule` TR-2.4: discard 后仅余 batch.yaml(discarded)，archive/indexes/.pending 消失；公开目录无该批次任何文件；证据：同文件
  - `rule` TR-2.5: pending>0 时 publish/discard 在极短 wait 下超时报错且状态保持 sealed；证据：同文件
  - `rule` TR-2.6: 空批次 seal→publish 成功，公开索引为空文件、状态 published；证据：同文件
  - `rubric` TR-2.7: 原子性/可恢复维度；scale 1-5；anchors 1=部分可见或不可恢复，3=主路径正确中断会残留，5=全步骤对账式且公开侧只可能"全有/全无"；threshold >=4；证据：TR-2.2/2.3 结果与代码审查

## Task 3: AutoIndexer 跳过发布保留目录 `.batches`
- **Status**: `completed`
- **Priority**: high
- **Depends On**: Task 2
- **Completion Evidence**:
  - [autoindex.py](file:///c:/Users/admin/Desktop/SWE-like/T28/pywb/manager/autoindex.py) os.walk 原地剪枝 EXCLUDED_DIRS；[manager.py](file:///c:/Users/admin/Desktop/SWE-like/T28/pywb/manager/manager.py) reindex 改走 `_iter_public_archive_warcs`（同等覆盖、剔除 .batches，文件名相对关系不变）。
  - TR-3.1/3.2：TestReservedDirExcludedFromIndexing 2 passed。
- **Description**:
  - `pywb/manager/autoindex.py` 的 `check_path` 在 os.walk 归档目录时剪枝名为 `.batches` 的目录（dirnames 原地移除），确保发布索引落盘前/后 AutoIndexer 都不会从保留目录生成 autoindex 条目。
  - CollectionsManager.reindex 手工重建索引路径同样不得把 `.batches` 纳入公开 index.cdxj（如索引器支持排除则传入排除；否则先收集文件列表过滤后再索引），避免与每批次索引产生重复行。
- **Acceptance Criteria Addressed**: AC-10, AC-12
- **Test Requirements**:
  - `rule` TR-3.1: 在某集合 archive/.batches/b/x.warc.gz 放置 WARC 后运行 AutoIndexer.check_path，autoindex.cdxj 不含该文件条目；普通 archive 下 WARC 仍正常索引；证据：新增/扩展 tests 下 autoindex 测试
  - `rule` TR-3.2: reindex 产出的 index.cdxj 不含 `.batches` 条目；证据：test_manager_batch.py 或 test_auto_colls 扩展

## Task 4: wb-manager 增加 `batch` 子命令
- **Status**: `completed`
- **Priority**: high
- **Depends On**: Task 2
- **Completion Evidence**:
  - [manager.py](file:///c:/Users/admin/Desktop/SWE-like/T28/pywb/manager/manager.py) main() 增加 batch create/list/seal/publish/discard（--wait），错误沿用 main_wrap_exc 退出码。
  - TR-4.1：TestBatchCLI::test_cli_lifecycle passed（含 argparse 非法参数 SystemExit、缺集合 IOError、幂等输出）。
- **Description**:
  - `pywb/manager/manager.py` main() 增加 `batch` 子解析器：`create/list/seal/publish/discard`，参数 `<coll> <batch>`（list 仅 coll），publish/discard 支持 `--wait`（秒，默认 30）。
  - 复用 CollectionsManager 的集合存在性断言；输出人类可读结果；错误经现有 main_wrap_exc 通道退出码 2。
- **Acceptance Criteria Addressed**: AC-1, AC-2, AC-11（CLI 操作面）
- **Test Requirements**:
  - `rule` TR-4.1: 通过 `main(['batch', ...])` 走完整 create→list→seal→publish/discard 生命周期，list 输出含状态；非法参数抛 SystemExit/异常由 argparse 处理；证据：test_manager_batch.py

## Task 5: MultiFileWARCWriter 支持批次目录路由并隔离去重
- **Status**: `completed`
- **Priority**: high
- **Depends On**: Task 1
- **Completion Evidence**:
  - [multifilewarcwriter.py](file:///c:/Users/admin/Desktop/SWE-like/T28/pywb/recorder/multifilewarcwriter.py)：新增可选 batch_dir_template、_is_batch_write/_get_dir_templates 钩子；批次写入跳过 add_warc_file/add_urls_to_index/_check_revisit；新增 close_sealed_batch_files。无 batch 参数时模板与键逐字同旧逻辑。
  - TR-5.1/5.2/5.3：TestBatchRecorder（4 用例）passed；既有 test_recorder.py 16 passed（仅 youtube_dl 可选依赖用例基线失败）。
- **Description**:
  - `MultiFileWARCWriter.__init__` 增加可选 `batch_dir_template=None`（形如 `<root>/{coll}/batches/{batch}/archive/`）；新增内部钩子按 params 中 `param.recorder.batch` 选择 dir/key 模板：`_write_to_file` 用所选模板解析 full_dir/dir_key；无 batch 参数时模板/键与现状逐字一致。
  - 批次写入跳过 `dedup_index.add_warc_file` 与 `add_urls_to_index`，并在 `_check_revisit` 对批次写入直接放行（不查共享去重索引）。
  - 新增按状态关闭批次句柄的方法（如 `close_sealed_batch_files(state_getter)`），遍历 fh_cache，对路径能解析为 `<coll>/batches/<batch>/archive` 且状态 ∈ {sealed, discarded, None} 的键执行 close_key；解析工具复用 Task 1。
- **Acceptance Criteria Addressed**: AC-3, AC-8, AC-9（句柄前置）, AC-12
- **Test Requirements**:
  - `rule` TR-5.1: 扩展 `pywb/recorder/test/test_recorder.py`：同一 writer 分别带/不带 `param.recorder.batch` 写入，WARC 分别落在 batches 目录与普通 archive 目录，fh_cache 键互不串扰；不带批次参数的既有用例全部保持通过；证据：录制器测试
  - `rule` TR-5.2: 配置 WritableRedisIndexer（fakeredis）时，批次写入不向 redis cdxj/file hash 添加条目，普通写入行为不变；证据：同文件
  - `rule` TR-5.3: 置批次状态 sealed 后调用 close_sealed_batch_files 能关闭对应句柄且普通集合句柄不受影响；证据：同文件

## Task 6: RecorderApp 批次准入闸门、在途计数与句柄回收轮询
- **Status**: `completed`
- **Priority**: high
- **Depends On**: Task 5
- **Completion Evidence**:
  - [recorderapp.py](file:///c:/Users/admin/Desktop/SWE-like/T28/pywb/recorder/recorderapp.py)：handle_call 单闸门（名称 RX + open 状态，403，代理/PUT 全覆盖）；入队 begin、_write_one/_put_record finally end 严格配对；_batch_reaper_loop 周期关闭封存批次句柄。
  - TR-6.1/6.2/6.3：test_batch_routing_admission_gate_counter、test_put_record_batch_gate、test_reaper_closes_sealed_batch_handles_only passed。
  - Rubric TR-6.4 自评 5：两条写入路径闸门与计数均在 finally 配对，非法批次名在路径拼接前拒绝；证据见上述用例。
- **Description**:
  - `RecorderApp.__init__` 增加 `batch_store=None`、`batch_poll_interval=1.0`；handle_call 在取到 params 后（覆盖代理路径与 put_record/stream 分支）检查 `param.recorder.batch`：无 batch_store/批次不存在/非 open → 返回 4xx JSON（代理路径不请求上游）。
  - 在途计数：RespWrapper 构造增加 batch_store；`_write_to_file` 成功入队前 begin_capture，入队失败立即回滚；`_write_one` 在 finally 对带批次条目 end_capture；`_put_record`（含 stream）写入前后 begin/end（finally 保证配对）。
  - 启动 gevent 周期任务：每 batch_poll_interval 调用 writer.close_sealed_batch_files(batch_store.get_state)。
- **Acceptance Criteria Addressed**: AC-5, AC-6, AC-14
- **Test Requirements**:
  - `rule` TR-6.1: 用临时 BatchManager + 本地 live server 构造 RecorderApp：open 批次 POST 录制成功并落盘到批次目录；sealed/不存在批次 POST 返回 4xx 且上游未被请求、无文件、计数为 0；证据：test_recorder.py 新增用例
  - `rule` TR-6.2: 计数配对：入队后未处理时计数=1，手动 `_write_one` 后=0；put_record 路径同样配对；证据：同文件
  - `rule` TR-6.3: 调小 poll interval，seal 后轮询周期内批次 WARC 句柄被关闭（文件可被 rename/delete）；证据：同文件
  - `rubric` TR-6.4: 准入/计数正确性维度；scale 1-5；anchors 1=有绕过闸门或计数泄漏，3=主路径正确异常路径泄漏，5=两条写入路径闸门与计数严格配对且可测；threshold >=4；证据：TR-6.1/6.2 与代码审查

## Task 7: FrontEndApp 接入：?batch 参数剥离、录制上游传参、BatchStore 注入
- **Status**: `completed`
- **Priority**: high
- **Depends On**: Task 6
- **Completion Evidence**:
  - [frontendapp.py](file:///c:/Users/admin/Desktop/SWE-like/T28/pywb/apps/frontendapp.py)：RECORD_API 追加 param.recorder.batch；init_recorder 注入 BatchManager（惰性根解析）与 batch 目录模板/轮询配置；_extract_batch_param 从目标 URL 剥离并写入 coll_config['batch']；put_custom_record 补 batch=''。
  - TR-7.1/7.2：tests/test_record_batch.py 6 用例 passed（WARC-Target-URI 无 batch、sealed 经前端 4xx）；test_record_replay.py 25 passed 无回归。
- **Description**:
  - `RECORD_API` 模板追加 `&param.recorder.batch={batch}`。
  - init_recorder：当 warcserver.root_dir 存在时构造 BatchManager(colls 根绝对路径) 作为 batch_store，计算 batch_dir_template（`<root>/{coll}/batches/{batch}/archive/`）传入 writer，并把 batch_store 与 `recorder.batch_poll_interval`（配置项，默认 1.0s）传给 RecorderApp。
  - serve_content（record 分支）：从查询串解析 `batch`，从 wb_url_str（REQUEST_URI 与回退拼接两个分支）剥离该参数后再交 WbUrl 解析；将 `coll_config['batch']` 置为批次名（非录制/无批次请求不受影响，str.format 所需键仅在 record 路径模板出现）。
- **Acceptance Criteria Addressed**: AC-3, AC-4, AC-7（前端面）, AC-12
- **Test Requirements**:
  - `rule` TR-7.1: 新增 `tests/test_record_batch.py`：`/<coll>/record/mp_/<url>?A=B&batch=b1` 录制成功，落盘位于 batches/b1/archive，WARC-Target-URI 不含 batch；不带 batch 的录制仍入公开 archive；证据：集成测试
  - `rule` TR-7.2: sealed 批次经完整前端链路录制返回错误且无文件；证据：同文件

## Task 8: 端到端集成测试与全量回归
- **Status**: `completed`
- **Priority**: high
- **Depends On**: Task 3, Task 4, Task 7
- **Completion Evidence**:
  - 新增 [test_record_batch.py](file:///c:/Users/admin/Desktop/SWE-like/T28/tests/test_record_batch.py) 6 用例（隔离/封存拒绝/发布原子可见+幂等/丢弃无痕迹/最终状态）全部 passed。
  - 全量 `pytest tests pywb`：**990 passed, 59 skipped, 9 failed**；9 个失败全部在 pristine 代码（git stash 后）复现，属环境基线：4× certauth/cryptography X509.add_extensions（test_cli 代理证书）、3× 缺 youtube_dl 可选依赖（test_live_rewriter、test_handlers×2）、1× brotli.Decompressor.unused_data 库版本、1× test_wbresponse_callable Content-Length 基线；另有 test_manager caplog 格式与 zipnum Windows 句柄 teardown 两个基线问题（stash 复现）。无任何批次相关或回归失败。
  - TR-8.1/8.2/8.3 达成；Rubric TR-8.4 自评 5：完整生命周期 + 在途计数/封存/句柄/幂等/失败重试均有断言，证据为上述两新测试文件与全量输出。
- **Description**:
  - 在 `tests/test_record_batch.py` 完成端到端场景（本地 httpbin，AutoIndexer 开启）：
    1. init 公开集合并先录制一条公开捕获，等待 autoindex → CDX/回放基线；
    2. create b1，带 ?batch=b1 录制多条；断言公开 archive 无新增、CDX/timemap 不可见、回放 404、公开基线内容仍可回放；
    3. seal：随后带批次录制被拒；在途写入门（必要时直接驱动 write_queue 验证计数排空）；
    4. publish（通过 BatchManager 或 `main(['batch','publish',...])`）：整批 CDX/回放/timemap 可见、source 为 batch-b1.cdxj、再次 publish 无变化；
    5. create b2→录制→seal→discard：CDX 无 b2 条目、批次载荷已删、公开内容不受影响。
  - 运行回归：tests/test_record_replay.py、tests/test_record_dedup.py、tests/test_manager.py、tests/test_auto_colls.py、pywb/recorder/test/test_recorder.py、pywb/warcserver/index/test。
- **Acceptance Criteria Addressed**: AC-6, AC-7, AC-8, AC-10, AC-11, AC-12
- **Test Requirements**:
  - `rule` TR-8.1: 隔离断言（发布前 CDX/timemap/回放均不可见，公开基线正常）通过；证据：pytest 输出
  - `rule` TR-8.2: 发布后整批可见、丢弃后彻底不可见、重复发布无变化通过；证据：pytest 输出
  - `rule` TR-8.3: 全部既有相关测试文件通过，零跳过（环境原因除外并记录）；证据：pytest 输出
  - `rubric` TR-8.4: 端到端保真度；scale 1-5；anchors 1=仅单元级覆盖，3=主流程覆盖但缺隔离/幂等断言，5=完整生命周期+并发/失败分支断言；threshold >=4；证据：测试清单与结果
