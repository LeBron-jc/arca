# ARCA — Adaptive Resource Control Agent

面向 openEuler 的生产级自适应资源管控 Agent 框架，基于 eBPF 采集 + 用户态策略决策 + LLM 智能调度 + sched_ext 内核执行。

## 架构

```
┌──────────────────────────────────────────────────────────┐
│                     SkillManager                          │
│                        │                                  │
│    ┌───────────────────┼───────────────────────────┐      │
│    │              SharedStore                       │      │
│    └───────────────────┼───────────────────────────┘      │
│                        │                                  │
├──────────┬──────────┬──┴───────┬──────────┬──────────────┤
│ CPUSched │NetworkPol│ResourceCtl│SecurityPol│ LLMDecision  │
│ (SCX调度)│(网络阻断) │(cg限流)   │(exec告警) │ (DeepSeek)   │
├──────────┴──────────┴──────────┴──────────┴──────────────┤
│                   eBPF 采集层                              │
├──────────┬──────────┬──────────┬──────────┬──────────────┤
│sched_sw  │tcp_send  │ /proc    │kprobe    │ SharedStore   │
│sched_wake│tcp_recv  │ /cgroup  │execve    │  → LLM API    │
└──────────┴──────────┴──────────┴──────────┴──────────────┘
```

**闭环**：eBPF 采集 → ringbuffer → 用户态 → SkillManager → 策略决策(+LLM) → pinned map → SCX 内核调度

## 文件结构

```
arca/
├── README.md
├── arca.conf              # 配置 (CPU/Network/Resource/LLM)
├── arca.service           # systemd 服务文件
├── deploy.sh              # 一键部署
├── start.sh               # 一键启动/停止/重启/状态
├── Makefile
│
├── include/               # 共享头文件
│   ├── arca.h             # 类型定义 + 共享枚举
│   ├── arca_sched.h       # SCX DSQ 常量
│   ├── skill.h            # Skill 抽象基类
│   ├── skill_manager.h    # 生命周期管理
│   ├── shared_store.h     # Skill间数据共享 (线程安全)
│   ├── dashboard.h        # ANSI 终端面板
│   ├── config.h           # INI 解析器 (零依赖)
│   └── log.h              # 结构化日志系统
│
├── src/
│   └── arca.cpp           # 主入口
│
├── skills/
│   ├── cpu/               # CPU 调度 Skill
│   │   ├── skill.yaml         (声明)
│   │   ├── cpu_skill.h / .cpp (实现)
│   │   ├── arca_trace.bpf.c   (eBPF 采集)
│   │   ├── arca_sched.bpf.c   (eBPF SCX vtime 调度)
│   │   └── arca_scx_ops.c     (C 包装)
│   ├── network/           # 网络策略 Skill
│   │   ├── skill.yaml
│   │   ├── network_skill.h / .cpp
│   │   └── network_trace.bpf.c  (eBPF)
│   ├── resource/          # 资源管控 Skill
│   │   ├── skill.yaml
│   │   └── resource_skill.h / .cpp
│   ├── security/          # 安全策略 Skill
│   │   ├── skill.yaml
│   │   ├── security_skill.h / .cpp
│   │   └── security_trace.bpf.c  (eBPF)
│   └── llm/               # LLM 决策 Skill
│       ├── llm_skill.h / .cpp
│
└── tools/
    ├── workload.c          # 5 种 profile 压测 (web/db/batch/mixed)
    ├── bench.sh           # CFS vs scx_simple vs ARCA
    └── multi_bench.sh     # 多场景对比
```

## 各 Skill 功能

### 1. CPUSchedSkill — CPU 调度优化

| 环节 | 实现 |
|------|------|
| 采集 | eBPF: `sched_switch` + `sched_wakeup` tracepoint |
| 特征 | 运行时/等待时/唤醒率/迁移次数/线程类型 |
| 分类 | 三维评分制 (interactive/cpu_bound/batch score) |
| 调度 | SCX vtime 加权公平 + idle CPU pick + INTERACTIVE 抢占 |
| 切片 | INTERACTIVE=1ms, NORMAL=5ms, CPU_BOUND=10ms, BATCH=20ms |

### 2. NetworkPolicySkill — 网络策略

| 环节 | 实现 |
|------|------|
| 采集 | kprobe: `tcp_sendmsg` + `tcp_cleanup_rbuf`，捕获 TX/RX 字节数 |
| 检测 | 每 PID 追踪流量速率，超 1MB/s 阈值自动标记 |
| 阻断 | 用户态 `kill(pid, SIGTERM)` (非内核 return -1，避免 kernel panic) |

### 3. ResourceCtrlSkill — 资源管控

| 环节 | 实现 |
|------|------|
| 采集 | `/proc/meminfo` + `/proc/stat` + cgroup v1/v2 |
| 告警 | 内存 > 阈值 或 CPU > 阈值 → ALERT 状态 |
| 限流 | cgroup `memory.max` + `cpu.max` 自动缩减 |

### 4. SecurityPolicySkill — 安全策略

| 环节 | 实现 |
|------|------|
| 采集 | kprobe: `__x64_sys_execve` |
| 检测 | `/tmp/` `/dev/shm/` 路径执行告警；Shell+curl/wget 下载器模式 |
| 降级 | BPF 加载失败时自动降级，不影响其他 Skill |

### 5. LLMDecisionSkill — LLM 智能决策

```
SharedStore 数据 → build_prompt() → DeepSeek API → parse_response() → 覆写 BPF map
```

| 环节 | 实现 |
|------|------|
| 输入 | 系统状态 + top 10 任务特征 + 规则分类结果 |
| 模型 | deepseek-chat (可配) |
| 输出 | `CLASSIFY: pid=X class=Y slice=Z reason=...` |
| 执行 | 覆写 `task_class_map`，SCX 调度实时生效 |
| 频率 | 可配 (默认 5s)，token 限制 2048 |
| 降级 | API 不可用时自动退回规则分类 |

**LLM 决策示例**：
```
pid=5924 → INTERACTIVE (1ms)   "Low runtime + high wakeup = interactive"
pid=5923 → CPU_BOUND  (10ms)   "High runtime + low wakeup = CPU-bound"
pid=5479 → BATCH      (20ms)   "Zero wakeup, no runtime = idle batch"
```

## 构建与运行

```bash
# 一键部署
sudo ./deploy.sh

# 配置 DeepSeek API key
vim arca.conf    # 填写 [llm] api_key
# 或: export DEEPSEEK_API_KEY="sk-..."

# 运行
sudo ./start.sh start      # 启动 (5 Skills + Dashboard)
sudo ./start.sh status     # 查看状态
sudo ./start.sh stop       # 停止

# systemd 部署
sudo cp arca.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now arca
```

## Benchmark

```bash
sudo ./tools/bench.sh           # 默认 3 轮 × 10s
sudo ./tools/multi_bench.sh     # web/db/batch/mixed 四场景
```

**实测数据**（openEuler 24.03 LTS-SP4, Linux 6.6.0-159, 4 核 8GB）：

| 调度器 | 交互延迟 | 对比 |
|--------|---------|------|
| CFS | 727 us | 基准 |
| scx_simple | 8980 us | 12.4x |
| **ARCA v4** | **701 us** | **3.6% 优** |

## 配置参数

```ini
[cpu]
interactive_slice_us  = 1000      # INTERACTIVE 时间片 (μs)
cpu_bound_slice_us    = 10000     # CPU_BOUND 时间片
batch_slice_us        = 20000     # BATCH 时间片
decay_ratio           = 0.75      # 统计衰减系数

[network]
block_threshold_bytes = 1000000   # 自动阻断流量阈值 (字节/秒)

[resource]
memory_alert_mb       = 6144      # 内存告警 (MB)
cpu_alert_pct         = 95        # CPU 告警 (%)

[llm]
api_key              =            # DeepSeek API key (也可用环境变量)
model                = deepseek-chat
temperature          = 0.3
call_interval_sec    = 5          # API 调用间隔
max_tokens           = 2048

[general]
refresh_interval_s    = 1         # Dashboard 刷新间隔
```

## 扩展

```cpp
// 1. 继承 Skill 基类
class MySkill : public arca::Skill { /* 实现 6 个虚函数 */ };

// 2. 注册
mgr.register_skill(std::make_shared<MySkill>());

// 3. 编译 → 运行
make && sudo ./start.sh restart
```

## 技术栈

- 内核：Linux 6.6.0-159 (openEuler 24.03 LTS-SP4)
- eBPF：CO-RE + tracepoint/kprobe + ringbuffer + struct_ops
- 用户态：C++11 + libbpf + ANSI Dashboard + popen(curl) HTTP
- 调度：sched_ext + vtime 加权公平 + 分类抢占 + LLM 决策
- 构建：GNU Make + clang/LLVM 17 + bpftool
