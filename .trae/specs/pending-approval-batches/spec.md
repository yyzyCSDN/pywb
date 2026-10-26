# 录制待审批次（Pending-Approval Batches）- 产品需求文档

## Overview
- **Summary**: 为 pywb 的 wb-manager 与录制模式增加"待审批次"能力：在**已有公开集合**内创建批次，把指定流量录制进隔离的批次存储；批次封存（seal）后不再接纳新捕获，已接纳捕获全部写完后可整批发布（publish，一次性进入公开 CDX/回放）或整批丢弃（discard，不留任何可检索痕迹）。
- **Purpose**: 支持"先录制、审核后公开"的工作流，保证发布前批次内容对普通 CDX 查询、回放和去重完全不可见，而集合内已公开内容始终可用；发布为原子提交，失败可重试且不重复导入。
- **Target Users**: 单机本地部署 pywb、使用 `/record/` 录制与 wb-manager 管理集合的归档操作人员。

## Goals
- 在已有公开集合（非新建集合）中创建/列出/封存/发布/丢弃批次。
- 通过录制请求显式指定批次；封存后拒绝新捕获。
- 发布前强隔离：批次 WARC 与 CDXJ 不被 AutoIndexer、CDX 目录源、去重索引看到。
- 发布时校验载荷引用可读，成功后整批原子可见；失败保持可重试的未发布状态；重复发布幂等。
- 丢弃后不留可检索条目，也不留可被外部解析使用的载荷引用。
- 不使用批次时，录制、索引、回放行为与现状完全一致。

## Non-Goals
- 不做多用户/权限/审批人模型，不做远程或分布式协调。
- 不做 Redis 去重开启时批次的"按批次去重索引"：批次录制期间不写入共享 Redis 去重索引，也不基于它产生 revisit（见假设 A-5）。
- 不做浏览器会话语义级别的批次自动粘连（如子资源自动继承批次）；批次按请求显式指定。
- 不改动 WACZ 导入、zipnum、固定路由集合（fixed-route/custom coll）的行为，不为其提供批次。
- 不新增外部依赖；不新增/改动文档文件（除非用户另行要求）。

## Background & Context
- 录制链路：`/<coll>/record/...` → 前端 `FrontEndApp.serve_record` → warcserver → `RecorderApp`（代理 live，缓冲 req/resp 入 gevent 队列）→ `MultiFileWARCWriter._write_to_file` 写入 `collections/<coll>/archive/rec-*.warc.gz`；参数中的 `param.recorder.coll` 经 `ParamFormatter` 决定写入目录。
- 可见性链路：`AutoIndexer.check_path` 递归遍历 `collections/<coll>/archive/`，把 WARC 增量合并进 `collections/<coll>/indexes/autoindex.cdxj`；`CacheDirectoryIndexSource` 列举 `collections/<coll>/indexes/` 下 `*.cdx(j)` 提供 CDX/回放；载荷由 `PrefixResolver` 以 `archive_paths`（`<root>/{coll}/archive/`）+ CDX `filename` 字段解析。
- 去重链路：仅在配置 Redis `dedup_policy` 时启用（`WritableRedisIndexer` 写 `pywb:<coll>:cdxj`，自动集合查询聚合 Redis 键 + 公开目录索引源）；默认本地部署不启用。
- 关键事实：
  - `AutoIndexer` 只走 `<coll>/archive`；目录索引源只列 `<coll>/indexes`。批次放在这两个目录之外即可天然隔离。
  - 写队列单消费者（gevent 绿程），写入参数在入队时快照（含 coll/batch），封存后晚到的已入队写入仍会落入批次目录。
  - 录制 WARC 句柄会缓存（fh_cache，idle 默认 600s 且无定时回收）；Windows 下打开的文件不能 rename/delete，需要封存后由录制进程关闭批次句柄。

## Functional Requirements

### 批次模型与存储
- **FR-1**: wb-manager 提供 `batch` 子命令：`create <coll> <batch>`、`list <coll>`、`seal <coll> <batch>`、`publish <coll> <batch> [--wait SECS]`、`discard <coll> <batch> [--wait SECS]`。批次只能创建在**已存在的公开集合**中；批次名校验规则与集合名一致（`^[\w][-\w]*$`），同一集合内不得重名。
- **FR-2**: 批次数据全部位于既有集合目录之下、且位于公开 `archive/` 与 `indexes/` 之外：
  ```
  collections/<coll>/batches/<batch>/
      batch.yaml                 # 状态元数据（state、时间戳等）
      archive/                   # 批次录制 WARC
      indexes/                   # 批次暂存 CDXJ（发布前生成）
      .pending                   # 已接纳未写完计数
  ```
  未发布批次不出现在 `<coll>/archive`、`<coll>/indexes` 中。
- **FR-3**: 批次状态机持久化于 `batch.yaml`：`open`（初始）→ `sealed` → `published` | `discarded`。
  - 非法转换必须报错且不改变状态：仅 open 可 seal；仅 sealed 可 publish/discard。
  - 状态写入必须原子（临时文件 + os.replace）。

### 指定批次录制
- **FR-4**: 录制请求通过查询参数显式指定批次：`/<coll>/record/<mod>/<url>?batch=<batch>`。
  - 前端必须把 `batch` 从被录制目标 URL 中剥离（WARC-Target-URI、上游 live 请求都不含该参数），并以 `param.recorder.batch` 传给 RecorderApp。
  - 不带 `batch` 参数的录制维持现有目录、现有文件命名与行为。
- **FR-5**: RecorderApp 对带批次参数的请求执行准入校验：批次存在且属于该集合、状态为 `open` 才放行；状态为 sealed/published/discarded 或批次不存在时返回 4xx JSON 错误，**不**代理 live、**不**写任何 WARC、**不**增加计数。该准入闸门对代理录制与 `put_record`（resource/stream）路径都生效。
- **FR-6**: 批次捕获写入 `collections/<coll>/batches/<batch>/archive/`，文件命名/滚动规则与现有录制一致；写入参数在准入时快照，封存不影响已准入捕获落盘。
- **FR-7**: 批次捕获的在途计数：代理路径在捕获进入写队列时 `pending +1`，写循环处理完成（含失败/跳过）后 `-1`；`put_record` 路径在同步写入前后 ±1。计数通过文件锁（portalocker，跨平台）维护，wb-manager 与服务进程读取同一计数。

### 封存与排空
- **FR-8**: `seal` 将 open→sealed。此后录制准入闸门拒绝新捕获；封存瞬间已在缓冲/已入队的捕获继续写完。
- **FR-9**: 录制进程周期性（可配置轮询间隔，默认 1s）检查写入器缓存的批次文件句柄，对状态已 sealed/discarded（或批次已不存在）的批次目录句柄执行关闭，使发布/丢弃在单进程本地部署下可移动/删除文件。
- **FR-10**: `publish` 与 `discard` 必须等待 pending 计数归零（默认轮询、可 `--wait` 限时；超时则报错退出，状态不变、可重试）。

### 发布前隔离
- **FR-11**: 发布之前，批次内容：
  - 不出现在集合的任何 CDX/CDXJ 查询结果、timemap 中；
  - 不可回放（closest/exact 查询 404）；
  - 不参与去重：批次写入不更新共享录制去重索引，批次暂存索引不被目录索引源枚举，因而其他批次与公开集合的去重/查询都看不到它；
  - 同集合已公开内容的 CDX、回放、时间地图在批次整个生命周期中保持正常。

### 发布
- **FR-12**: `publish` 流程（sealed 且计数归零后）：
  1. 对 `batches/<batch>/archive/` 全部 WARC 生成有序 CDXJ 暂存索引（复用现有 CDX 索引器，文件名相对批次 archive 根）；
  2. **载荷校验**：逐条校验 CDX 的 `filename/offset/length` 引用仍存在且可读（能打开并覆盖 offset..offset+length 区间）；任一不可读 → 不做任何迁移/发布变更，批次保持 `sealed`，命令报错（可重试）；
  3. 将批次 WARC 目录**一次性整体重命名**到公开归档下保留子目录 `collections/<coll>/archive/.batches/<batch>/`（同卷原子目录改名）；`AutoIndexer` 必须跳过 `.batches` 目录，防止发布索引落盘前出现部分可见；
  4. 将 CDXJ 的 filename 改写为 `.batches/<batch>/<warc名>` 后，**原子落盘**为 `collections/<coll>/indexes/batch-<batch>.cdxj`（临时文件 + os.replace）；
  5. 状态原子更新为 `published`。
- **FR-13**: 原子性与幂等：发布成功后整批同时可见，任何步骤失败/进程中断都不得产生"部分批次可见"（公开索引中只存在完整文件或不存在）。中断后重试发布必须能对账续做（WARC 已迁移/索引已落盘则跳过该步），最终公开索引文件内容唯一、无重复行；对已 `published` 的批次再次执行 publish 直接成功返回且不重复导入。
- **FR-14**: 空批次（无任何捕获）允许封存与发布：发布后为空索引文件，不产生任何可见捕获。

### 丢弃
- **FR-15**: `discard`（sealed、计数归零后）删除 `batches/<batch>/archive/`、`batches/<batch>/indexes/` 与计数文件，仅保留 `batch.yaml` 作为 discarded 墓碑（不含任何 CDX/载荷引用，且不位于任何被索引目录）。丢弃的批次从未进入公开 `archive/`、`indexes/`，因此 CDX/回放不可检索，也不存在外部可解析的载荷引用。文件删除在句柄未释放时按等待窗口重试，超时保持 sealed 并报错。

### 兼容性
- **FR-16**: 未使用批次（无 `batch` 参数、无 batches 目录）时，录制写入路径/命名、AutoIndexer 行为、CDX/回放、wb-manager 既有命令与现有测试保持不变；新增代码在无批次场景不产生额外文件系统操作或行为差异。

## Non-Functional Requirements
- **NFR-1**: 现有测试套件全部通过；新增单元/集成测试覆盖状态机、隔离、原子发布、失败重试、幂等、丢弃、录制准入与在途排空。
- **NFR-2**: Windows 兼容（测试与运行环境为 Windows）：使用 os.replace、路径用 os.path.join/sep、文件锁用 portalocker；不得依赖 rename 已打开文件，统一通过 FR-9 的句柄回收 + 操作等待窗口解决。
- **NFR-3**: 不新增第三方依赖；测试不依赖外网（本地 httpbin）。
- **NFR-4**: 最小侵入：对 `MultiFileWARCWriter`、`RecorderApp`、`FrontEndApp`、`AutoIndexer` 的改动以可选参数/钩子方式加入，默认路径逻辑不变。

## Constraints
- **Technical**: Python 3、gevent 单进程模型；warcio/portalocker 既有依赖；文件型本地录制索引（autoindex.cdxj）。
- **Business**: 范围限定单进程本地部署及其录制索引；未使用批次保持原行为。
- **Dependencies**: wb-manager CLI 可能与运行中的服务进程并发操作同一批次目录（跨进程状态/计数文件）。

## Assumptions
- **A-1**: 批次按请求以 `?batch=<id>` 查询参数显式指定（API 与每个捕获请求携带）；不实现浏览器会话内子资源自动继承批次。
- **A-2**: 单进程指一个 pywb 服务进程 + 可选的 wb-manager CLI 进程；不保证多个服务进程并发写同一集合。
- **A-3**: 发布后 WARC 永久保留在 `archive/.batches/<batch>/` 保留目录中，由每批次一份的公开 CDXJ 引用；不与 `autoindex.cdxj` 合并。
- **A-4**: 崩溃后若 `.pending` 残留正数（进程异常且未释放计数），发布/丢弃等待超时后报错，由人工确认无录制进程后可重试；本版本不做基于 PID 的自动失效。
- **A-5**: 启用 Redis 去重时，带批次的录制既不查共享去重索引也不写入它（批次内始终写完整 response/request 对）；发布后因批次索引进入公开 `indexes/` 目录，目录索引源会自然使其参与后续去重。默认（无 Redis）去重本就不存在。
- **A-6**: 固定路由/自定义集合（config 中声明的非目录集合）不支持批次；对动态目录集合（enable_auto_colls）生效。

## Acceptance Criteria

### AC-1: 在既有公开集合中创建批次且目录隔离
- **Type**: `rule`
- **Given**: 已用 wb-manager init 出公开集合 `c1`
- **When**: 执行 `wb-manager batch create c1 b1`
- **Then**: 生成 `collections/c1/batches/b1/{archive,indexes}` 与 `batch.yaml(state=open)`；`collections/c1/archive`、`collections/c1/indexes` 内容不变
- **Pass Condition**: 目录/文件存在性与 state=open 断言通过；对不存在集合、非法批次名、重名创建报错
- **Evidence**: 新增 `tests/test_manager_batch.py` 单元测试

### AC-2: 批次状态机非法转换被拒绝且持久化
- **Type**: `rule`
- **Given**: 批次处于 open/sealed/published/discarded 各状态
- **When**: 执行 seal/publish/discard 的合法/非法组合
- **Then**: 仅 open→sealed、sealed→published/discarded 被接受；非法转换抛错且 batch.yaml 状态不变；进程重载后状态仍正确
- **Pass Condition**: 全部合法/非法转换矩阵断言通过
- **Evidence**: 单元测试

### AC-3: 带 batch 参数的录制写入批次目录且目标 URL 被剥离参数
- **Type**: `rule`
- **Given**: 集合 c1 存在 open 批次 b1
- **When**: 请求 `/c1/record/mp_/http://httpbin.org/get?A=B&batch=b1`
- **Then**: WARC 写入 `collections/c1/batches/b1/archive/`，公开 `archive/` 无新增；WARC-Target-URI 为 `http://httpbin.org/get?A=B`（无 batch）
- **Pass Condition**: WARC 位置与 WARC-Target-URI 断言通过
- **Evidence**: 集成测试 + 录制器测试

### AC-4: 不带批次参数的录制行为不变
- **Type**: `rule`
- **Given**: 同一环境既有录制测试
- **When**: 请求 `/c1/record/mp_/<url>`（无 batch）
- **Then**: WARC 仍写入 `collections/c1/archive/`，命名模板、滚动、autoindex 行为与改动前一致
- **Pass Condition**: 既有 `tests/test_record_replay.py`、`pywb/recorder/test/test_recorder.py` 全绿
- **Evidence**: 既有测试运行结果

### AC-5: 封存后拒绝新捕获
- **Type**: `rule`
- **Given**: 批次 b1 已 sealed
- **When**: 以 `?batch=b1` 发起录制（代理与 PUT resource/stream 各一）
- **Then**: 返回 4xx，不代理 live、批次 archive 不新增文件、pending 不增加；无 batch 参数的普通录制不受影响
- **Pass Condition**: 状态码、目录无新增、错误 JSON 断言通过
- **Evidence**: 录制器测试 + 集成测试

### AC-6: 已接纳捕获写完并计数归零后才允许发布/丢弃
- **Type**: `rule`
- **Given**: b1 seal 时仍有已入队未写完的捕获（计数>0）
- **When**: 立即 publish/discard
- **Then**: 命令等待计数归零；未归零时超时报错且状态仍 sealed；归零后执行成功；在途写入完整落入批次 WARC
- **Pass Condition**: 计数增减配对、等待/超时分支、在途数据完整性断言通过
- **Evidence**: 单元测试 + 录制器测试

### AC-7: 发布前批次对普通 CDX、timemap、回放不可见
- **Type**: `rule`
- **Given**: 批次 b1 已录制若干 URL，处于 open 或 sealed
- **When**: 查询集合 c1 的 cdx/timemap 与 closest 回放这些 URL
- **Then**: 结果中不含 b1 的任何捕获，回放 404
- **Pass Condition**: CDX 行数/内容、timemap、回放状态码断言通过
- **Evidence**: 集成测试

### AC-8: 批次内容不参与去重且已公开内容正常
- **Type**: `rule`
- **Given**: 公开集合已有捕获；另一批次 b2 正在录制
- **When**: b2 录制重复内容；同时查询/回放既有公开内容
- **Then**: 共享录制去重索引不出现 b2 条目（配置 Redis 去重时），b2 暂存索引不被目录索引源枚举；公开 CDX/回放结果与录制前完全一致
- **Pass Condition**: Redis 键内容、CDX/回放断言通过
- **Evidence**: 去重录制测试扩展

### AC-9: 发布校验载荷引用，失败保持可重试未发布状态
- **Type**: `rule`
- **Given**: sealed 批次的某个 WARC 被删除或移动导致 CDX 引用不可读
- **When**: 执行 publish
- **Then**: 报错；`indexes/batch-b1.cdxj` 与 `archive/.batches/` 均不存在；状态仍 sealed；恢复文件后重试发布成功
- **Pass Condition**: 失败现场无公开变更、重试成功断言通过
- **Evidence**: 单元/集成测试

### AC-10: 成功发布整批原子可见且重复发布幂等
- **Type**: `rule`
- **Given**: sealed 且计数归零、载荷可读的批次 b1
- **When**: publish 成功；再次 publish
- **Then**: 全部捕获同时出现在 CDX/timemap 并可回放；公开索引仅 `indexes/batch-b1.cdxj` 一份、无重复行；AutoIndexer 未为 `.batches` 生成额外索引；再次 publish 成功且文件/行数不变，状态 published
- **Pass Condition**: 发布前后 CDX 集合差异恰为整批、重复发布无变化；模拟"WARC 已迁移但状态未更新"中断后续做成功
- **Evidence**: 集成测试

### AC-11: 丢弃不留可检索条目或外部载荷引用
- **Type**: `rule`
- **Given**: sealed 批次 b2（含捕获）
- **When**: 执行 discard
- **Then**: `batches/b2/archive`、`indexes`、`.pending` 被删除，仅留 discarded 墓碑；公开 archive/indexes 从未包含其内容；CDX/回放查不到；磁盘上不存在可由公开索引解析到的该批次载荷文件
- **Pass Condition**: 文件系统与 CDX/回放断言通过
- **Evidence**: 单元/集成测试

### AC-12: 未使用批次时系统行为不变
- **Type**: `rule`
- **Given**: 不含任何 batches 目录的既有部署
- **When**: 运行全量既有测试（录制、回放、CDX、autoindex、manager、dedup）
- **Then**: 全部通过
- **Pass Condition**: 选定测试子集（test_record_replay、test_record_dedup、test_manager、test_auto_colls、pywb/recorder/test/test_recorder、warcserver index 测试）全绿
- **Evidence**: pytest 输出

### AC-13: 变更最小侵入与可维护性
- **Type**: `rubric`
- **Dimension**: 新增能力以可选参数/独立模块接入，默认路径无分支负担；命名、复用现有索引/合并工具、错误信息清晰
- **Scale**: 1-5
- **Anchors**: 1 = 复制粘贴式大改核心流程、默认路径被污染；3 = 功能可用但侵入点生硬；5 = 独立 BatchManager + 少量可选钩子，默认行为零差异，复用 CDXObject/CDX 索引器/os.replace 等既有设施
- **Pass Threshold**: >= 4
- **Evidence**: 代码审查与 diff 结构

### AC-14: 单进程并发状态一致性
- **Type**: `rubric`
- **Dimension**: 服务录制进程与 wb-manager CLI 进程并发下，准入、计数、封存、句柄回收、发布/丢弃的正确性与失败可恢复性
- **Scale**: 1-5
- **Anchors**: 1 = 存在竞态导致部分可见/计数永久卡死；3 = 常见顺序正确但边界（在途封存、中断重试、Windows 句柄）缺失；5 = 单闸门准入、计数配对、轮询排空、句柄回收、原子状态/索引落盘、对账幂等均有实现与测试
- **Pass Threshold**: >= 4
- **Evidence**: 并发/中断场景测试与代码审查

## Open Questions
- 无阻塞性开放问题；A-1（批次按请求显式指定，不做会话粘连）、A-3（发布载荷保留于 `archive/.batches/<batch>/`）、A-5（Redis 去重下批次不写共享索引）为设计假设，审批阶段可被修正。
