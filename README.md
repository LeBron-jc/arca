# ARCA - Adaptive Resource Control Agent

面向 openEuler 的自适应资源管控 Agent，基于 eBPF 采集 + 用户态策略决策 + sched_ext 调度执行。

## 架构

```
┌─────────────────────────────────────────────────────────┐
│                    SkillManager                          │
├──────────────┬──────────────┬─────────────┬─────────────┤
│ CPUSched     │ NetworkPolicy│ ResourceCtrl│ SecurityPolicy│
│ (SCX调度)     │ (网络管控)     │ (资源监控)    │ (安全监控)     │
├──────────────┴──────────────┴─────────────┴─────────────┤
│                   eBPF 采集层                             │
├──────────────┬──────────────┬─────────────┬─────────────┤
│ sched_switch │ tcp_sendmsg  │ /proc/cgroup │ kprobe/exec │
│ sched_wakeup │ tcp_recv     │ /proc/meminfo│              │
└──────────────┴──────────────┴─────────────┴─────────────┘
```

**闭环**：eBPF 采集 → ringbuffer → 用户态 → 策略决策 → pinned map → SCX 内核调度

## 文件结构

```
arca/
├── arca.cpp              入口 main（4 Skills 注册 + 主循环）
├── arca.h                共享类型（task_event, task_class, stats_val）
├── arca.conf             可调参数配置（INI 格式）
│
├── skill.h               抽象 Skill 基类（init/start/stop/collect/policy/act）
├── skill_manager.h       生命周期管理 + 状态展示
├── dashboard.h           终端实时面板（ANSI 彩色）
├── config.h              INI 解析器（零依赖）
│
├── cpu_skill.h/cpp       CPU 调度 Skill：评分分类 + vtime SCX
├── arca_trace.bpf.c      eBPF: sched_switch + sched_wakeup tracepoint
├── arca_sched.bpf.c      eBPF: SCX struct_ops（vtime 公平 + 抢占）
├── arca_sched.h          DSQ ID 定义
├── arca_scx_ops.c        C 包装：SCX open/load/attach/reuse_map
│
├── network_skill.h/cpp   网络策略 Skill
├── network_trace.bpf.c   eBPF: kprobe tcp_sendmsg + tcp_cleanup_rbuf
│
├── resource_skill.h/cpp  资源管控 Skill（cgroup + /proc 采集）
│
├── security_skill.h/cpp  安全策略 Skill
├── security_trace.bpf.c  eBPF: kprobe __x64_sys_execve
│
├── workload.c            混合压测（CPU-bound + Interactive + Batch）
├── bench.sh              CFS vs scx_simple vs ARCA 对比脚本
└── Makefile
```

## 各 Skill 功能

### 1. CPUSchedSkill（CPU 调度）

**采集**：eBPF tracepoint 在每个调度事件上记录
- `sched_switch`：prev_pid→next_pid，运行时长
- `sched_wakeup`：唤醒进程 pid，等待时长
- 每进程统计：累计运行时、等待时、唤醒次数、切换次数、CPU 迁移次数

**分类**：多维评分制（每个 task 在 3 个维度打分，最高者胜出）
```
INTERACTIVE = 高唤醒率 + 短运行 + 低等待
CPU_BOUND   = 低唤醒率 + 长运行 + 少迁移
BATCH       = 中唤醒率 + 长运行 + 规律模式
```

**调度**：
- select_cpu：INTERACTIVE 任务 → SCX_DSQ_LOCAL + scx_bpf_kick_cpu(SCX_KICK_PREEMPT) 立即抢占
- enqueue：vtime 加权入队（INTERACTIVE 短 slice、CPU_BOUND 长 slice）
- dispatch：vtime 公平消费单一全局 DSQ
- running/stopping：vtime 记账

### 2. NetworkPolicySkill（网络策略）

- kprobe 挂载 `tcp_sendmsg` + `tcp_cleanup_rbuf`
- 维护 per-PID 流量统计 + block_list
- （扩展能力：连接限速、流量阻断）

### 3. ResourceCtrlSkill（资源管控）

- 读取 `/proc/meminfo`、`/proc/stat` 采集系统级 CPU/内存
- 读取 cgroup 文件系统采集 IO/OOM
- 超阈值自动 Alert（可配：memory_alert_mb, cpu_alert_pct）

### 4. SecurityPolicySkill（安全策略）

- kprobe 挂载 `__x64_sys_execve`，捕获所有进程执行
- 检测 `/tmp/`、`/dev/shm/` 路径执行（可疑行为告警）
- BPF 加载失败时自动降级，不影响其他 Skill

## 构建与运行

```bash
cd /home/cuijian/arca
make                          # 构建所有组件
sudo ./arca                   # 启动 4 Skills + 终端 Dashboard
sudo ./arca arca.conf        # 指定配置文件
```

Dashboard 刷新示例：
```
╔══════════════════════════════════════════════════════════════╗
║  ARCA  Adaptive Resource Control Agent  |  2026-07-06 00:10:09 ║
╚══════════════════════════════════════════════════════════════╝

═══ CPU Scheduling ═══
  Events: 6652  (4900/s)  |  Tasks: 77  |  SCX: enabled
  UNKNOWN  57  INTERACTIVE  13  CPU_BOUND   2  BATCH   5
  ████████████████████████████████████████████████████████████████

═══ Network Policy ═══
  Status: running  |  bytes_tx: 0  |  flows: 0  |  blocked: 0

═══ Resource Control ═══
  Status: normal  |  mem: 2112MB  |  cpu: 12%  |  oom: 0
```

## Benchmark

```bash
sudo ./bench.sh               # 默认 10s x 2 轮
sudo ./bench.sh 10 3          # 10s x 3 轮
```

**实测数据**（openEuler 24.03-LTS-SP4, Linux 6.6.0-159, 4核 8GB）：

| 调度器 | 交互延迟 | 对比 CFS |
|--------|---------|-----------|
| CFS | 727 us | 基准 |
| scx_simple | 8980 us | 12.4x 差 |
| **ARCA v3** | **701 us** | **3.6% 优** |

## 配置参数 (arca.conf)

```ini
[cpu]
interactive_min_score = 0.4    # 分类置信度阈值
interactive_slice_us  = 1000   # INTERACTIVE 时间片 (μs)
cpu_bound_slice_us    = 10000  # CPU_BOUND 时间片
batch_slice_us        = 20000  # BATCH 时间片
decay_ratio           = 0.75   # 统计衰减系数

[resource]
memory_alert_mb       = 6144   # 内存告警 (MB)
cpu_alert_pct         = 95     # CPU 告警 (%)

[general]
refresh_interval_s    = 1      # Dashboard 刷新间隔
scx_enabled           = true   # 启用 SCX 调度
```

## 扩展新 Skill

只需 3 步：

```cpp
// 1. 继承 Skill 基类，实现 6 个虚函数
class MySkill : public arca::Skill {
    int init() override;
    int start() override;
    int stop() override;
    int collect() override;
    int policy() override;
    int act() override;
    std::vector<SkillMetrics> metrics() override;
};

// 2. 在 arca.cpp 中注册
mgr.register_skill(std::make_shared<MySkill>());

// 3. 更新 Makefile 添加编译规则
```

## 技术栈

- 内核：Linux 6.6.0-159 (openEuler 24.03 LTS-SP4)
- eBPF：CO-RE + tracepoint/kprobe + ringbuffer + struct_ops
- 用户态：C++11 + libbpf 1.3 + ANSI Dashboard
- 调度：sched_ext + vtime 加权公平 + 分类抢占
- 构建：GNU Make + clang/LLVM 17 + bpftool
