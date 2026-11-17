# 基于 pidfd 的容器退出监听设计说明

## 0. 背景与问题定义

embedshim 是内嵌在 containerd 进程里的 task runtime 插件，没有独立常驻的
shim 进程（daemonless）。容器进程（runc-init 以及 exec 出来的进程）都不是
embedshim 的直接子进程，因此不能靠 `wait(2)` 感知退出。当前实现由两部分组成：

1. **pidfd + epoll（`pkg/pidfd`）**：用数字 pid 调 `pidfd_open(2)` 换成
   pidfd，挂到一个全局 `Epoller`（`pkg/pidfd/epoll.go`）上，进程终止时 pidfd
   可读，epoll 线程触发回调；
2. **eBPF `sched_process_exit` raw tracepoint（`pkg/exitsnoop` +
   `bpf/exitsnoop.bpf.c`）**：按 pid 在 `tracing_tasks` map 里登记任务，
   进程退出时 BPF 程序把退出码写入 `exited_events` map，key 是用户态分配的
   `traceEventID`，解决"非父进程拿不到退出码"的问题。

### 0.1 核心竞争窗口

风险出在"拿到 pid"到"建立监听"之间。当前两条注册路径都是先有数字 pid、再换
pidfd：

- init 进程：`runc create` 写 pidfile，`initProcess.Create()` 读 pidfile
  （`init_process.go:209`），之后 `monitor.traceInitProcess()`
  （`monitor.go:71`）才 `pidfd.Open`；
- exec 进程：`embedshim-runcext` 包装进程从 pidfile 读到 exec pid
  （`cmd/embedshim-runcext/exec.go:147`），经 sync pipe 把 pid 传回 containerd，
  容器侧再 `pidfd.Open`（`exec_process.go:333`）。

如果原进程在这个窗口内已经退出（OOM、被手动 kill、短生命周期任务），同一个
数字 pid 被一个无关进程复用，`pidfd_open` 会成功返回指向**新进程实例**的
fd。后果有两种：

- 新进程一直存活 → 容器被误判为仍在运行，`Wait` 永久阻塞；
- 新进程退出 → 把无关进程的退出当成容器退出。

容器密度高、生命周期短的环境里 pid 回绕很快，这个窗口必须关闭。

### 0.2 当前已有的缓解措施及其不足

| 机制 | 位置 | 不足 |
|---|---|---|
| init 注册后检查 runc-init 持有的 `exec.fifo` fd 身份 | `checkRuncInitAlive`（`runtime_utils.go:111`） | 只适用于 runc-init；依赖 runc 内部实现细节（fifo 路径、fd 布局），换 crun/youki 即失效；只检查一次 |
| 注册后再 `pidfd_send_signal(pidfd, 0)` 探活 | `monitor.go:118` | 只能证明"fd 指向的进程此刻活着"，证明不了它是目标实例；pid 被复用时探活照样成功 |
| BPF map 按 pid 登记 + pidns dev/ino 校验 | `exitsnoop.bpf.c:62` | pidns 校验只能挡住跨 pidns 的复用，同 pidns 内的 pid 复用挡不住；且 map key 是数字 pid |
| BPF 记录 `start_boottime` | `exitsnoop.bpf.c:74`、`ExitStatus.StartBoottime` | 字段已采集但用户态从未使用，没有任何比对逻辑 |
| exec 路径的 sync 协议两阶段确认 | `runcext/sync.go`、`exec.go:190` | 缩短了窗口但没有消除：`pidfd_open` 仍按数字 pid 做，包装进程自身也有一段 pid→pidfd 的空窗 |
| reload 时比对 `taskInfo.TraceID` | `monitor.go:184` | 只在 containerd 重启路径生效，正常注册路径无此保护 |

结论：pidfd 本身一旦拿到手就绑定确定的进程实例（pid 复用不影响已打开的
fd），问题只在"用 pid 换 pidfd"这一步。设计必须保证换回来的 fd 确实指向
目标实例。

---

## 1. 进程实例身份核验：主路径与回退路径

### 1.1 两个候选方案

**方案 A：pidfd_open + 进程身份核验（事后核验）**

拿到 pidfd 后，从 `/proc/<pid>/stat` 的第 22 列读取 `starttime`（进程自
boot 以来的时钟滴答数，时钟源为 `sysconf(_SC_CLK_TCK)`，通常 100Hz），与
注册时刻已知的基准身份比对。`starttime` 在内核里对应
`task_struct->start_boottime`（BPF 程序已经在采集该字段），进程实例在整个
生命周期内不变，pid 复用必然产生新的 `starttime`。

基准身份的来源：

- init 进程：注册前读一次 `/proc/<pid>/stat` 记录 `starttime`，同时保留
  现有的 `exec.fifo` 检查作为 runc 场景的二次佐证；
- exec 进程：`embedshim-runcext` 在 `pidfd_open` 成功后、sync 消息里把
  `starttime` 一并回传（它和目标 pid 同生命周期窗口，读到的就是目标实例）；
- reload 路径：BPF `tracing_tasks` 的 value 里增加 `start_boottime` 字段，
  作为持久化基准（map pin 在 bpffs，containerd 重启后仍在）。

核验通过才允许 `Epoller.Add`。核验失败（`ESRCH` 或 `starttime` 不匹配）
按"取得 pidfd 之前进程已退出"处理，见第 4 节。

**方案 B：创建子进程时直接拿到 pidfd（源头消除）**

`clone3(2)` 带 `CLONE_PIDFD` 标志，子进程一创建父进程手里就有指向该实例的
pidfd，不存在"先 pid 后 fd"的窗口。`CLONE_PIDFD` 自 Linux 5.3 起支持。

但 embedshim 自己并不 `clone` 容器进程——进程是 runc 创建的。本仓库能控制
的只有 exec 包装器 `embedshim-runcext`，而真正 exec 进容器的进程也是 runc
`libcontainer` 内部 `clone3` 出来的，包装器拿到的只是 pidfile。因此：

- 对 init 进程，方案 B 需要修改 runc（让 runc 在 `clone3` 时带
  `CLONE_PIDFD` 并通过协议把 fd 传给上层），超出本仓库边界，不能作为默认
  依赖；
- 对 exec 进程，现有 sync pipe 机制（`ProcSyncExecPid`/`ProcSyncExecStatus`）
  已经是"源头同步"思路的弱化版：包装器在 runc exec 返回的同一同步窗口内
  完成 `pidfd_open` 和存活检查，把窗口压缩到极短。彻底方案 B 同样需要
  runc 支持 SCM_RIGHTS 传递 pidfd。

### 1.2 定稿：A 为主路径，B 为可选增强，不支持时走降级轮询

| 路径 | 适用场景 | 状态 |
|---|---|---|
| **主路径：pidfd_open + starttime 身份核验 + epoll** | init 与 exec 全部场景，不依赖 runc 改造 | 本设计落地 |
| **增强路径：CLONE_PIDFD 源头取 fd** | 未来 runc 支持回传 pidfd 后，exec 路径优先采用；检测到运行时支持即自动启用 | 预留接口，本次不实现 |
| **回退路径：starttime 核验 + 轮询** | 内核不支持 pidfd、seccomp 禁用、fd 资源不足 | 见第 2 节 |

选择依据：

1. embedshim 对容器进程没有父子关系、也不控制 runc 的 `clone` 参数，
   方案 B 在当前依赖边界内无法独立落地，只能作为演进方向；
2. 方案 A 的 `starttime` 核验是通用机制，不绑定 runc 内部实现，可以替换掉
   `checkRuncInitAlive` 这种 runc 专属逻辑，对 crun/youki 同样有效；
3. BPF 程序已经在采集 `start_boottime`，用户态只需补比对，改动集中在
   `pkg/pidfd` 和 `monitor`，风险可控。

### 1.3 内核版本要求

| 能力 | 最低内核 | 说明 |
|---|---|---|
| `pidfd_open(2)` | 5.3 | 主路径依赖；5.3 之前可用 `clone`+`pidfd_send_signal` 的间接方式，但本项目不实现 |
| pidfd 支持 `poll(2)`/epoll（退出通知） | 5.3 | `pkg/pidfd/epoll.go` 的基础 |
| `pidfd_send_signal(2)` | 5.1 | 探活与 `Kill` 路径（exec 已在用，`exec_process.go:225`） |
| `waitid(P_PIDFD, ...)` | 5.4 | 仅对**本进程的子进程**有效；runcext 包装器用它做 exec 同步窗口的非阻塞检查（`exec.go:193`） |
| raw tracepoint | 4.18 | exitsnoop BPF 附着方式 |
| BTF / CO-RE | 5.4 | BPF 程序可移植编译 |
| BPF link | 5.7 | `link.AttachRawTracepoint` |
| `clone3` + `CLONE_PIDFD`（增强路径） | 5.3（clone3 为 5.3，CLONE_PIDFD 同期） | 预留 |

**综合最低门槛：内核 ≥ 5.7** 才能跑完整主路径（与 README 现有
Requirements 一致，需补充 `pidfd_open ≥ 5.3` 一条）。内核在 5.3~5.7
之间时 pidfd 可用但 BPF link/CO-RE 不可用，整体仍不满足；**内核 < 5.3
或 seccomp 显式拦截 `pidfd_open` 时，自动进入第 2 节的轮询降级路径**。

能力探测在插件初始化（`TaskManager.init`，`plugin.go:185`）时做一次：
对自身 `getpid()` 调 `pidfd_open` 自检，区分 `ENOSYS`（内核不支持）、
`EPERM`（seccomp/安全策略禁止）与成功后关闭。探测结果记入 monitor 的
全局能力状态。

---

## 2. 降级路径：轮询 + 身份比对

### 2.1 触发条件与行为约束

三种情况进入降级：

1. 初始化能力探测发现 `pidfd_open` 返回 `ENOSYS`；
2. 返回 `EPERM`/`EACCES`（容器 seccomp 或 LSM 策略禁止）；
3. 运行期 `pidfd_open` 或 `epoll_ctl` 返回 `EMFILE`/`ENFILE`/`ENOMEM`
   （fd 或内存资源不足）。

降级后的监听方式：单个 goroutine 定期对目标做两件事——

- `kill(pid, 0)` 探活：`ESRCH` 表示进程已不存在；
- 每次探活同时读 `/proc/<pid>/stat` 的 `starttime` 与基准比对：
  `starttime` 变化说明 pid 已被复用，**原任务按"已退出、退出码未知"处理**，
  绝不能把新实例的状态当作目标的状态。

约束（对应需求中的硬性要求）：

- **允许发现退出变晚，不允许误判已退出**：只有 `ESRCH` 且此前连续观测到
  的 `starttime` 始终匹配，才宣告退出；`EPERM`（进程存在但无权发信号）
  一律视为存活；
- **判成存活后必须继续检查**：轮询任务在显式 `Delete` 之前不退出，不存在
  "一次判定存活就不再管"的状态；
- 轮询间隔自适应：默认 1s，连续存活 N 次后退避到上限 5s，收到 `Kill`
  请求后短窗口内缩短到 100ms，兼顾高密度场景的开销与退出感知延迟。

### 2.2 降级作用域与升级策略：按任务降级，条件恢复后自动升级

**定稿：降级以单个任务为单位，不做全局开关；每次注册重新尝试主路径，
成功即升级。**

依据：

1. 资源不足（`EMFILE`）通常是瞬时、局部的——一个任务注册时 fd 耗尽，不
   代表后续 fd 回收后其他任务也不能用 pidfd。全局降级会把一次瞬时故障
   放大成整个进程的能力丧失；
2. 能力型失败（`ENOSYS`/`EPERM`）是稳定的，每次注册尝试的成本只是一次
   立刻失败的 syscall，换取的是"运维放开 seccomp 策略后无需重启
   containerd 即自动恢复"的语义；
3. 每个任务自带 watcher 状态，生命周期与任务对齐，删除任务即回收
   goroutine，不会累积。

每个任务的 watcher 状态机记录实际路径，持久化到 bundle 目录下新增的
`watch.json`（与现有 bundle 文件并列，`pkg/bundle` 管理），字段：

```json
{
  "mode": "pidfd-epoll | polling",
  "pid": 12345,
  "starttime": 12345678,
  "starttime_clk_tck": 100,
  "degrade_reason": "ENOSYS | EPERM | EMFILE | ENFILE | ENOMEM | \"\"",
  "updated_at": "2026-11-18T..."
}
```

`mode` 同时在内存中的 `initProcess`/`execProcess` 上暴露，供 `State`
查询和日志输出。reload（`reload.go`）时读 `watch.json` 恢复 watcher：
主路径任务重新 `pidfd_open` 并核验 `starttime`；轮询任务直接重建轮询。

### 2.3 降级路径的退出码

轮询只能感知"没了"，拿不到退出码。退出码来源按优先级：

1. BPF `exited_events`（只要 BPF 子系统可用，降级的只是 pidfd，BPF 仍在
   记录）；
2. runc state（仅 init，`runc state` 在 stopped 后保留 status）；
3. 都取不到 → 记录为**未知**，写入明确原因（`exit code unknown: process
   reaped before lookup` 之类），**禁止填 0 或复用现有 `unexpectedExitCode
   = 128` 冒充真实码**。现有代码在 BPF map 查不到时直接
   `SetExited(unexpectedExitCode)`（`monitor.go:126` 等三处），新设计改为
   `SetExitedUnknown(reason)`，状态里区分"真实退出码"与"未知"。

---

## 3. 退出状态的获取与回收：谁在 wait，冲突在哪

### 3.1 当前所有回收子进程的角色盘点

| 角色 | 位置 | 回收对象 | 方式 |
|---|---|---|---|
| `embedshim-runcext` 包装器 | `app.go:55` `reaper.SetSubreaper(1)` | 自己 fork 的 runc 进程，以及同步窗口内成为孤儿子的 exec 目标 | `waitid(P_PIDFD, WNOHANG\|WNOWAIT)` 探活 + `wait4` 真正回收（`exec.go:193-212`） |
| containerd 主进程（embedshim 所在进程） | 未调用 `SetSubreaper`，Go runtime 默认 `SIGCHLD` 处理 + `exec.Cmd.Wait` | 仅自己 `exec` 出去的 runc 命令行进程（`runc create/start/...`） | `os/exec` 内部 `wait4` |
| 宿主机 PID 1（systemd） | 进程外 | runc-init、detach 后的 exec 进程（reparent 后） | 系统级回收 |
| BPF 程序 | 内核态 | 不做回收，只在 `do_exit` 路径读 `task_struct->exit_code` | tracepoint |

关键事实：**embedshim 主进程既不是容器进程的父进程，也不是 subreaper**，
因此它对 runc-init / 长期运行的 exec 进程没有也不应该有 `wait` 资格。
BPF 方案能成立正是因为 tracepoint 在回收动作之前触发，与谁 wait 无关。

### 3.2 可能冲突的位置

1. **runcext 的 `wait4(execPid)`（`exec.go:205`）**：这是全仓库唯一对容器
   进程本身的回收调用。它成立的前提是包装器通过 `SetSubreaper` 成了
   subreaper、且 exec 目标在同步窗口内退出并 reparent 给它。风险点：
   - 如果 containerd 侧未来也设置 subreaper（containerd 配置或别的插件
     所为），exec 目标可能 reparent 给 containerd 而非 runcext，`wait4`
     返回 `ECHILD`，当前代码会报错回滚。设计上保持"embedshim 主进程
     **永不** SetSubreaper、永不 wait 容器 pid"的边界，并在文档与代码
     注释中固化；`ECHILD` 改为可容忍：拿不到 wait status 时退回 BPF
     事件，不视为失败。
2. **Go runtime 的 SIGCHLD 收割**：Go 运行时会自动回收被 reparent 到本
   进程的子进程。若任何容器进程意外成为 containerd 的子进程，其退出码会
   被 runtime 静默收走，用户态 `wait` 只能得到 `ECHILD`。这进一步说明
   退出码不能依赖 wait 族 syscall，BPF map 是唯一稳定来源。
3. **`waitid(P_PIDFD)` 的父子限制**：`P_PIDFD` 形式的 waitid 只允许目标
   是调用者的子进程（内核 5.4 起；非父 `pidfd_wait` 长期未合并）。所以
   主进程侧**不能**用 pidfd waitid 取 init 的退出码，runcext 里的用法
   只因为它在 exec 同步窗口内恰好是父/subreaper。设计中明确：pidfd 在
   本项目里只承担"退出通知（epoll 可读）"和"定向发信号"两个职责，退出
   码一律走 BPF。

### 3.3 "状态还能回收"与"已经取不到"的区分

进程退出后、被父进程 wait 之前是 zombie：`/proc/<pid>` 仍在，
`pidfd_open` 仍成功（pidfd 可以指向 zombie），BPF 事件已写入。被回收
后 `/proc/<pid>` 消失，pidfd 保持打开仍可读（这是它比数字 pid 可靠的
地方），但退出码只有此前留存的渠道能取到。

处理规则：

- **zombie（状态还能回收）**：BPF `exited_events` 命中 → 用其中
  `exit_code`；runcext 场景 `waitid` 命中 → 用 `siginfo` 并把 raw wait
  status 经 `ExitedEventFromWaitStatus` 写入同一张 map（现有逻辑，
  `exec_process.go:374`），统一出口。
- **已回收且 map 无事件**：不承诺 pidfd 能找回退出码——pidfd 只通知
  "实例终止"，不含 status。标记 `exit code unknown` 并写明原因（map
  key 不存在 / BPF 程序未加载 / 事件已被清理），**绝不填成功码 0**。
- **BPF 事件与 epoll 通知的顺序竞争**：内核 `do_exit` 中
  `exit_notify()`（含 pidfd 通知）先于 `sched_process_exit` tracepoint
  执行。因此 epoll 回调读 BPF map 时事件可能尚未写入，当前代码直接判
  `ErrKeyNotExist` → 128，是真实缺陷。新设计在回调内加有界重试
  （例如 50ms 间隔、最多 1s 或若干次），超时仍无事件才落"未知"。

---

## 4. 边界情况逐一处理

### 4.1 取得 pidfd 之前进程已经退出

注册流程改为固定的四段式，全程持有 monitor 锁（沿用现有
`traceInitProcess` 的加锁粒度）：

1. 读基准身份：`/proc/<pid>/stat` 取 `starttime`；`/proc` 已消失
   （`ENOENT`）→ 直接判定目标已退出，进入退出收尾，不做 `pidfd_open`；
2. `pidfd_open`：返回 `ESRCH` → 同上，判定已退出；
3. 身份核验：再次读 `/proc/<pid>/stat` 比对 `starttime`，不一致 → pid
   已复用，原任务判定已退出（退出码走 4.2 的渠道），顺手关闭指向无关
   进程的 fd，**绝不**把它加入 epoll；
4. 登记 BPF map（`Trace`）→ 二次 `pidfd_send_signal(0)` 探活 →
   `Epoller.Add`。探活失败说明登记期间退出，清理 map 项后进退出收尾。

退出收尾顺序：先查 `exited_events`（带 3.3 的有界重试），再查 runc
state（init），都失败则 unknown。这样覆盖"窗口内退出且 pid 已复用"和
"窗口内退出仍是 zombie"两种子情况。

### 4.2 退出状态已被别的回收逻辑取走

按 3.3 的规则：zombie 阶段 BPF 一定已写事件（tracepoint 在 wait 之前），
正常情况下 map 命中。map 未命中的现实原因只剩 BPF 未加载/被卸载/事件
已被 Delete 清理或 map 容量淘汰（`max_entries=2048`，高密度场景需要
调大并加监控）。此时：

- 状态置 stopped，退出码字段标 unknown 并记录原因字符串；
- 上报给 containerd 的 `runtime.Exit.Status` 使用一个带"未知"语义的
  表达，而不是 0/128；现有 `unexpectedExitCode=128` 的三处用法
  （`monitor.go:126,189,204`；exec 回调里的 255，`exec_process.go:401`）
  全部收敛到同一个 `unknownExitStatus` 类型并附 reason。

### 4.3 同一个进程被重复注册监听

分两类：

- **同一任务的重复注册**（重试、reload 与正常注册并发）：以
  `traceEventID` 为幂等键。monitor 内维护 `traceEventID → watcher` 注册
  表，注册前查表：已存在且 `starttime` 一致 → 返回已有 watcher，不重复
  `pidfd_open`、不重复插 BPF map；已存在但 `starttime` 不一致 → 拒绝并
  报错（身份冲突，说明调用方传错了 pid）。
- **`Epoller.Add` 层面**：现有实现对同一 fd 重复 Add 直接报错
  （`epoll.go:43`），保留该防线；另外 BPF `Trace` 用的是
  `UpdateNoExist`，同一 pid 重复登记会返回 `EEXIST`，注册表先行拦截后
  这个错误只作为兜底告警。
- exec 进程的 `reserveExecID`（`shim.go:316`）继续保证 execID 维度不
  重复，与 watcher 幂等键形成两层防护。

### 4.4 监听线程组里的非主线程

BPF 程序开头 `if (pid != tid) return 0;`（`exitsnoop.bpf.c:54`）已经
保证只响应线程组领导（tgid 级）退出，非领导线程退出不会产生事件。
pidfd 本身也是 tgid 粒度：fd 指向整个线程组，组领导退出、组内仍有线程
时 fd 不会可读，直到整个线程组终止。

需要写明的规则：

- 注册入口只接受 tgid（runC 创建的进程号、pidfile 内容均为 tgid），
  对 `/proc/<pid>/stat` 读到的 pid 与目标数字不一致（传入的是 tid）的
  情况直接拒绝并记日志；
- 文档明确不支持监听单个线程的退出语义，exec/init 的契约都是进程级；
- 核验身份时比对 `Tgid` 字段（`/proc/<pid>/status`）与目标 pid 相等，
  防止误用 tid。

### 4.5 监听建立期间任务被删除

删除路径（`shim.Delete` → `initProcess.delete`，`shim.go:296`）与注册
路径都走 monitor 锁串行化，补充以下规则：

- 注册流程每一步失败/退出都要回滚已占资源：BPF map 项
  （`DeleteTracingTask` + `DeleteExitedEvent`，现有 defer 模式
  `monitor.go:109-114` 保留）、pidfd close、epoll interest 删除、
  `watch.json` 删除；
- watcher 回调与 Delete 并发时，以 `traceEventID` 的注销标记为准：
  Delete 先在注册表打 tombstone 再清理资源；回调触发后先查表，看到
  tombstone 则只做资源回收、不调用 `SetExited`（避免向已删除任务的
  `waitBlock` channel 重复 close——现有 `setExited` 无条件
  `close(p.waitBlock)`，重复触发会 panic，stoppedState 的 no-op
  `SetExited` 是目前唯一的防护，tombstone 是更直接的防线）；
- 轮询降级模式下，Delete 负责停止该任务的 ticker 并等待 watcher
  goroutine 退出，防止任务删了轮询还在、以及对复用后 pid 的误报。

---

## 5. 新旧退出监听机制对比

### 5.1 事件触发方式

| 维度 | 当前实现 | 本设计落地后 |
|---|---|---|
| 退出通知 | pidfd epoll 可读（`Epoller.Run`） | 不变；轮询任务为周期探活发现 `ESRCH` |
| 身份绑定 | 数字 pid 换 fd，仅 runc-init 有 exec.fifo 佐证、exec 无核验 | 一律 `starttime`（+pidns）核验后才监听；fd 指向确定实例 |
| 退出码 | BPF `exited_events`，查不到填 128/255 | BPF 优先、runc state 次之，取不到标 unknown 并附原因，不再伪造码 |
| BPF 事件时序 | epoll 先于 tracepoint 时直接判失败 | 有界重试吸收时序差 |
| 能力缺失 | `newMonitor` 失败即插件初始化失败，无降级（`plugin.go:201`） | 能力探测 + 按任务自动降级轮询，记录 `mode`/`reason` |
| 重复注册 | fd 级报错、BPF `EEXIST` 报错 | `traceEventID` 幂等，重试安全 |
| reload | `repollingInitProcess` 比对 TraceID（`monitor.go:139`） | 增加 `starttime` 核验与 `watch.json` 状态恢复，exec 仍不跨重启（execStore 未 pin，行为不变） |

### 5.2 先后顺序与延迟变化

正常路径（主路径生效时）的时序：

```
进程 do_exit
  ├─ exit_notify() → pidfd 可读 → epoll 线程唤醒
  │                    └─ 回调：有界重试等 BPF 事件（新增，0~1s）
  └─ tracepoint → BPF 写 exited_events、删 tracing_tasks
回调拿到事件 → SetExited → close(waitBlock)
```

- 主路径的稳态延迟与现状基本相同（epoll 通知是亚毫秒级），仅在事件
  慢于通知时多出最多重试窗口的等待，消除了当前的误判 128；
- 降级路径延迟上界 = 轮询间隔（1~5s 自适应，Kill 后 100ms），这是
  有意接受的代价，换取正确性不回退；
- 注册路径增加两次 `/proc/<pid>/stat` 读取和一次 map 查询，微秒级，
  相对 `runc create` 的百毫秒级开销可忽略。

### 5.3 对上层 Wait / Delete / State 可观察差异

- **Wait**：`initProcess.Wait`/`execProcess.Wait` 仍是阻塞在
  `waitBlock` 上，通道关闭语义不变。差异只有两点：① 降级时返回时间
  变晚（可预期、有上界）；② 返回的 `Exit.Status` 可能是带 unknown
  标记的状态而非伪造的 128/255——消费方（containerd 任务服务、CRI）
  需要把 unknown 作为合法退出状态处理，事件里附带 reason 文本。
- **Delete**：流程不变（`delete` 里 runc delete、IO 关闭、rootfs
  umount），新增 watcher 资源回收（pidfd、ticker、注册表项、
  `watch.json`、BPF map 事件清理）。对调用方耗时无明显影响；并发
  Delete/退出的 panic 隐患（重复 close channel）被 tombstone 消除，
  属于可观察的可靠性提升。
- **State / Status**：状态机（created/running/paused/stopped/deleted）
  不变。新增可观察信息：监听模式（pidfd-epoll/polling）、降级原因、
  退出码是否可信。通过日志和 `watch.json` 暴露，不改变 gRPC 状态枚举，
  保持对 containerd 接口的兼容。
- **Kill**：exec 路径已经用 `pidfd_send_signal` 定向发信号
  （`exec_process.go:225`），天然不受 pid 复用影响；init 路径仍走
  `runc kill`。降级任务的 Kill 后缩短轮询间隔，保证杀完能快速感知。

---

## 6. 落地改动清单（供实现阶段参考）

1. `pkg/pidfd`：新增身份核验工具（读 `/proc/<pid>/stat` 的
   `starttime`/`Tgid`，封装 `OpenAndVerify(pid, wantStarttime)`）；
2. `monitor.go`：重写 `traceInitProcess` 为四段式注册；exec 回调复用
   同一套核验与有界重试；删除 `unexpectedExitCode` 伪造码，引入
   `unknownExitStatus{reason}`；
3. 新增 `pkg/pidfd/poller.go`（或 monitor 内）：轮询 watcher、
   自适应间隔、tombstone 注销、注册幂等表；
4. `plugin.go`：初始化能力探测（`ENOSYS`/`EPERM` 区分），
   `newMonitor` 不再因 pidfd 不可用而整体失败；
5. BPF：`task_info` 增加 `start_boottime` 字段并在登记时写入；
   `max_entries` 调大并加 map 满的告警计数；
6. bundle：新增 `watch.json` 持久化与 reload 恢复（`reload.go`）；
7. `cmd/embedshim-runcext/exec.go`：sync 消息携带 `starttime`；
   `wait4` 的 `ECHILD` 改为可容忍并退回 BPF 事件；
8. README：补齐内核版本矩阵（`pidfd_open ≥ 5.3`、综合门槛 5.7、
   seccomp 要求允许 `pidfd_open`/`pidfd_send_signal`）。
