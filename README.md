# ARCA — Adaptive Resource Control Agent

面向 openEuler 的生产级自适应资源管控 Agent，基于 12 个 eBPF 感知点 + LLM 统一决策 + SCX 内核调度 + 系统级控制。

## 架构

```
  ┌─────────────────────────────────────────────────────────────┐
  │                    12 eBPF Hooks                            │
  │  CPU (6)    │ Network (4)   │ Resource (2)  │ Security (3)  │
  │  switch     │ tcp_sendmsg   │ page_alloc    │ exec          │
  │  wakeup     │ tcp_recv      │ block_issue   │ exit          │
  │  blocked    │ tcp_connect   │               │ mount         │
  │  runtime    │ tcp_retransmit│               │               │
  │  wait       │               │               │               │
  │  fork       │               │               │               │
  └──────┬──────────┬──────────────┬────────────────┬──────────┘
         │          │              │                │
         ▼          ▼              ▼                ▼
  ┌──────────────────────────────────────────────────────────────┐
  │                     SharedStore                              │
  │  cpu.top_tasks / net.tx_bytes / system.mem / sec.exec_count  │
  └──────────────────────────────────────────────────────────────┘
         │
         ▼
  ┌──────────────────────────────────────────────────────────────┐
  │               LLM Decision Engine (DeepSeek)                  │
  │                                                              │
  │  输入: 全系统状态 (CPU + 网络 + 资源 + 安全)                    │
  │  输出: 4 种指令                                               │
  │    PRIORITY:pid=X value=Y    → SCX vtime 优先级(-100~+100)    │
  │    BLOCK:pid=X               → bpf_send_signal(9) 内核杀进程   │
  │    THROTTLE:type=mem value=N  → per-PID cgroup 隔离           │
  │    ALERT:pid=X severity=Y    → 安全告警                       │
  └──────────────────────────────────────────────────────────────┘
         │
    ┌────┴────┬──────────┬──────────┐
    ▼         ▼          ▼          ▼
  SCX调度  网络阻断   资源限流   安全拦截
```

**闭环**：eBPF 采集 → SharedStore 数据池 → LLM 全局决策 → 4 路执行

## 文件结构

```
arca/
├── README.md
├── arca.conf / arca.service / deploy.sh / start.sh / Makefile
├── include/     (7 个头文件)
├── src/         (arca.cpp 主入口)
├── skills/
│   ├── cpu/     (5 文件: skill + 2 eBPF + C 包装)
│   ├── network/ (3 文件: skill + eBPF)
│   ├── resource/(3 文件: skill + eBPF + skeleton)
│   ├── security/(3 文件: skill + eBPF)
│   └── llm/     (2 文件: 统一决策引擎)
└── tools/       (workload.c + bench.sh + multi_bench.sh)
```

## 感知体系 (12 eBPF hooks)

| 分类 | Hook | 采集指标 |
|------|------|---------|
| CPU | `sched_switch` | runtime, switch_count, prev_state(I/O/D/R) |
| CPU | `sched_wakeup` | wakeup_count, wakeup 间隔 |
| CPU | `sched_stat_blocked` | I/O 阻塞精确时长(ns) |
| CPU | `sched_stat_runtime` | 内核级 CPU 执行时长 |
| CPU | `sched_stat_wait` | 就绪队列等待时长 |
| CPU | `sched_process_fork` | 父子关系 + fork 计数 |
| 网络 | `tcp_sendmsg` | TX 字节 + PID 关联 |
| 网络 | `tcp_cleanup_rbuf` | RX 字节 |
| 网络 | `tcp_connect` | 新连接事件 |
| 网络 | `tcp_retransmit_skb` | 重传事件(网络质量) |
| 资源 | `__alloc_pages_nodemask` | 页面分配频率 |
| 资源 | `block_rq_issue` | 磁盘 I/O 次数 |
| 安全 | `sched_process_exec` | 进程执行 + 文件名 |
| 安全 | `sched_process_exit` | 进程退出 |
| 安全 | `sys_enter_mount` | mount 操作 |

## 决策与执行

### LLM 统一决策引擎

LLM 看到所有 4 路数据，输出 4 种指令：

```
PRIORITY: pid=5924 value=80 reason=High wakeup rate, interactive shell
PRIORITY: pid=8000 value=-30 reason=Batch job, low priority ok
BLOCK: pid=9001 reason=10MB/s flood, abnormal traffic pattern
THROTTLE: type=mem value=5120 reason=Memory pressure at 5.2GB/8GB
ALERT: pid=9002 severity=4 reason=Execution from /tmp/ suspicious
```

### 4 路执行

| Agent | 采集 | LLM 指令 | 执行机制 |
|-------|------|---------|---------|
| CPUSched | 6 tracepoint | PRIORITY | SCX: vtime += priority × slice / 10；priority≥80 抢占 |
| NetworkPolicy | 4 kprobe | BLOCK | `bpf_send_signal(9)` 内核态 SIGKILL |
| ResourceCtrl | 2 kprobe + /proc | THROTTLE | 创建 per-PID sub-cgroup + echo 限制 |
| SecurityPolicy | 3 tracepoint | ALERT | `bpf_send_signal(9)` 阻止 /tmp/ 执行 |

## 构建与运行

```bash
sudo ./deploy.sh                    # 一键部署

# 配置 API key
echo "DEEPSEEK_API_KEY=sk-xxx" >> arca.conf  # 或 export 环境变量

sudo ./start.sh start               # 启动 (5 Skills + Dashboard)
sudo ./start.sh status              # 查看状态
sudo ./start.sh stop                # 停止
```

## Benchmark

```bash
sudo ./tools/bench.sh               # CFS vs ARCA
sudo ./tools/multi_bench.sh         # 4 场景 (web/db/batch/mixed)
```

## 配置参数

```ini
[llm]
api_key           =                 # DeepSeek API key
model             = deepseek-chat
call_interval_sec = 10              # LLM 调用间隔

[resource]
memory_alert_mb   = 6144            # 内存告警阈值
cpu_alert_pct     = 95              # CPU 告警阈值

[general]
refresh_interval_s = 1              # Dashboard 刷新间隔
```

## 技术栈

- 内核: Linux 6.6.0 (openEuler 24.03 LTS-SP4)
- eBPF: CO-RE + tracepoint/kprobe + struct_ops + bpf_send_signal
- 调度: sched_ext + vtime 优先级 (-100~+100) + SCX_KICK_PREEMPT
- 用户态: C++11 + libbpf + ANSI Dashboard
- LLM: DeepSeek API via popen(curl), 零依赖
- 构建: GNU Make + clang/LLVM 17 + bpftool
