# 录制待审批次（Pending-Approval Batches）- Independent Review

- [ ] CP-R1: 批次创建/布局隔离/状态机/CLI 行为正确
  - **Type**: `rule`
  - **Covers**: AC-1, AC-2, AC-11（CLI 面）
  - **Evidence**: Pending

- [ ] CP-R2: 指定批次录制落入隔离目录、目标 URL 被剥离；无批次参数行为不变
  - **Type**: `rule`
  - **Covers**: AC-3, AC-4
  - **Evidence**: Pending

- [ ] CP-R3: 封存后录制准入闸门拒绝新捕获（代理与 PUT 路径），不落盘不计数
  - **Type**: `rule`
  - **Covers**: AC-5
  - **Evidence**: Pending

- [ ] CP-R4: 发布/丢弃等待已接纳捕获写完（pending 排空），在途数据完整
  - **Type**: `rule`
  - **Covers**: AC-6
  - **Evidence**: Pending

- [ ] CP-R5: 发布前批次对普通 CDX/timemap/回放不可见，已公开内容全程正常
  - **Type**: `rule`
  - **Covers**: AC-7
  - **Evidence**: Pending

- [ ] CP-R6: 批次不参与共享去重（Redis 与目录索引源），批次间互不可见
  - **Type**: `rule`
  - **Covers**: AC-8
  - **Evidence**: Pending

- [ ] CP-R7: 发布时载荷引用校验失败则零公开变更、状态保持 sealed、可重试
  - **Type**: `rule`
  - **Covers**: AC-9
  - **Evidence**: Pending

- [ ] CP-R8: 成功发布整批原子可见；中断可对账续做；重复发布幂等不重复导入
  - **Type**: `rule`
  - **Covers**: AC-10
  - **Evidence**: Pending

- [ ] CP-R9: 丢弃后无可检索条目、无外部可解析载荷引用，仅留墓碑
  - **Type**: `rule`
  - **Covers**: AC-11
  - **Evidence**: Pending

- [ ] CP-R10: 未使用批次时既有测试与行为保持；新增失败仅为已复现环境基线
  - **Type**: `rule`
  - **Covers**: AC-12
  - **Evidence**: Pending

- [ ] CP-U1: 最小侵入与可维护性
  - **Type**: `rubric`
  - **Covers**: AC-13
  - **Scale**: 1-5
  - **Anchors**: 1 = 核心流程被复制式改动、默认路径被污染；3 = 功能可用但侵入生硬；5 = 独立 BatchManager + 可选钩子，默认零差异，复用既有 CDX/索引/原子设施
  - **Pass Threshold**: >= 4
  - **Evidence**: Pending

- [ ] CP-U2: 单进程并发状态一致性
  - **Type**: `rubric`
  - **Covers**: AC-14
  - **Scale**: 1-5
  - **Anchors**: 1 = 有竞态可致部分可见/计数卡死；3 = 主顺序正确但边界缺失；5 = 单闸门准入、计数配对、轮询排空、句柄回收、原子落盘、对账幂等均齐备且有测试
  - **Pass Threshold**: >= 4
  - **Evidence**: Pending

## Review History

### Review R1
- **Result**: `fail`
- **Evidence**:
  - 独立只读审查（全新上下文 general_purpose_subagent）实跑：test_manager_batch.py+test_record_batch.py 32 passed；TestBatchRecorder 4 passed；record_replay/record_dedup/auto_colls/warcserver-index 272 passed, 3 skipped；相邻套件仅复现给定基线失败。
  - CP-R1/R2/R3/R5/R6/R7/R8/R10 = pass；CP-U1 = pass（4/5）。
  - CP-R4、CP-R9 = fail；CP-U2 = 3/5（未达阈值）。
  - Actionable finding：代理捕获"已准入、缓冲中（未入队）"窗口不被 pending 计数覆盖；seal 后立即 publish/discard 可提前执行 → discard 后迟到捕获经 writer `_open_file` 的 makedirs 复活载荷；publish 后迟到 WARC 写回已迁走的 staging 永不索引、幂等发布不对账。
  - Advisory（5，low）：reaper 路径启发式；coll_config 共享 dict 既有模式；锁超时静默（修复准入即计数后对代理路径自然消除）；published 批次目录残留 .pending；recorder 直连 coll 未校验（localhost 既有信任模型）。
- **Route**: 见 Issue I-1（high）；advisory I-2/I-5 纳入顺手修复，其余记录不修（既有模式/超出范围）。
