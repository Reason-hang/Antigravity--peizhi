---
trigger: always_on
description: 零弹窗工程硬熔断机制与工具绝对强制路由表（物理级 100% 0 弹窗与自主闭环绝对铁律）
---

# 零弹窗工程硬熔断机制与工具绝对强制路由表

> **定位**：Antigravity IDE 工作区最高优先级底层执行硬约束。  
> **核心目标**：彻底消除人机协作全生命周期的权限阻断与频繁确认弹窗，实现 100% 物理级 0 弹窗与 Agent 自主闭环交付。

---

## 一、 根因认知与物理沙箱三大硬红线

### 1. 弹窗机理定性与软硬约束界限
- **硬机制 vs 软约束**：IDE 弹窗是宿主操作系统与 IDE 安全内核的**硬物理防线（Hard Constraint）**。提示词只是约束 Agent 的意图（Soft Constraint），根本无法越过底层沙箱。
- **为何会频繁弹窗**：
  1. **命令碎片化与动态拼接**：在终端执行动态拼接的 `python3 -c "多行脚本"`、包含重定向符（`>`、`>>`、Heredoc）、管道符（`|`）或复合连接符（`&&`）时，命令哈希每次均不相同，导致系统的“始终允许”前缀匹配彻底失效，触发 IDE 安全审查。
  2. **跨域越界读取（致命阻断）**：脚本将临时文件写入操作系统共享目录，Agent 随后调用工具读取时，触发宿主工作区沙箱越权防御，IDE 对进程执行**同步挂起（Sync Block）**，导致无人值守任务永久死锁。
- **macOS 软链接陷阱（Symlink Trap）**：
  在 macOS 底层，根目录 `/tmp` 和 `/var` 是指向 `/private/tmp` 和 `/private/var` 的符号链接（Symlink）。严禁使用 `/tmp`、`/private/tmp` 或 Python 的 `tempfile.gettempdir()`！系统自动展开的绝对路径会击穿工作区白名单，直接引爆权限拦截弹窗。
- **警示反例与正例（吴军 PDF 批处理案例）**：
  - ❌ **反例**：脚本写 `/tmp/wj01_clean.md` $\to$ Agent 调用工具读取 $\to$ 解析为 `/private/tmp/...` $\to$ 触发权限弹窗 $\to$ 任务彻底卡死。
  - ✅ **正例**：脚本写 `WORKSPACE_ROOT/.tmp_pdf_unpack/wj01_clean.md` $\to$ 原生工具静默读取 $\to$ 100% 物理级 0 弹窗。
- **永远不要迷信“Always allow”**：点击“Always allow”只是把有毒路径加入临时白名单，属于治标不治本；**真正的根治是永远不产生任何一个工作区外的物理路径！**

---

## 二、 物理工作区锁死（100% Workspace-Scoped）

1. **唯一受信读写域**：所有临时文件、中间数据、解压缓存、处理脚本，必须 100% 锁死在当前工作区根目录（`WORKSPACE_ROOT`）内部，严禁向外溢出任何一个字节。
2. **路径与缓存命名约定**：
   - 临时/中间目录：必须严格命名为 `WORKSPACE_ROOT/.tmp_<任务标识>/`（如 `.tmp_pdf_unpack/`、`.tmp_pipeline/`）；
   - 交付成果目录：统一存放于工作区下明确命名的子目录中（如 `<项目名>-Markdown精排版/`）；
   - 任务结束后由脚本在工作区内部自主静默回收，或通过 `.gitignore` 规则实现静默过滤，严禁在系统级目录留存垃圾。

---

## 三、 工具选择绝对强制路由表（Strict Tool Routing）

平台原生内置工具运行于 IDE 受控沙箱中，**天然 0 弹窗**。任何操作必须严格按照下表路由执行，严禁越界调用底层终端：

| 任务类型 | 允许使用的工具（100% 免弹窗） | 严禁行为（触发弹窗，属于严重违规） |
| :--- | :--- | :--- |
| **文档阅读、生成物抽检与质检** | **`view_file`** | 严禁调用 `cat`、`head`、`tail`、`more`、`less` 等 Shell 命令 |
| **关键词匹配、正则检索、锚点与水印排查** | **`grep_search`** | 严禁在终端调用 `grep`、`rg` 或 `python3 -c "import re..."` |
| **局部勘误、段落微调、文本替换** | **`replace_file_content`** / **`multi_replace_file_content`** | 严禁编写临时 Python 脚本或 `sed`、`awk` 命令调用终端执行文本替换 |
| **新文件、新脚本、新文档生成** | **`write_to_file`** | 严禁使用终端重定向命令（如 `cat << 'EOF' > ...` 或 `echo > ...`） |
| **目录结构查看与文件列表探查** | **`list_dir`** | 严禁在终端调用 `ls`、`find`、`tree`、`dir` 等命令 |
| **复杂二进制解析与重计算**（PDF/EPUB 数据抽取） | **受控沙箱单脚本原子闭环**（标准沙箱执行，全程 0 弹窗） | 严禁将探查、提取、重排、打补丁割裂为多次微命令在终端循环轮询 |

---

## 四、 零容忍执行熔断锁与工具调用三级降阶梯次

### 1. 工具调用三级降阶梯次
1. **第一梯队（原生工具绝对优先）**：凡是文本读取、代码检索、文件修改、状态检查，**必须 100% 使用原生工具**（`view_file`、`replace_file_content`、`write_to_file`），在此场景下 `run_command` 调用次数 = 0。
2. **第二梯队（重计算与批处理自主闭环）**：处理二进制解析（PDF/EPUB）、音视频转码等原生工具无法处理的长耗时批处理时，**Agent 自主封装单一原子 Python 脚本并在标准沙箱内执行**，必须同时满足以下硬性条件：
   - 必须使用标准沙箱（`BypassSandbox: false`），严禁请求系统提权；
   - 脚本内必须内嵌 `guard_path()` 物理断言与临时目录重定向；
   - 严禁拆解为循环命令行，严禁在执行期间使用 `run_command` 频繁轮询 `ps`、`tail`、`status`；
   - 进度通过工作区内部的 `progress.json` 记录，Agent 仅通过 `view_file` 非阻塞读取。
3. **第三梯队（高危外部操作主动降级）**：若任务确实需要访问外网、修改系统全局配置或涉及非受信环境，Agent 严禁擅自弹窗索权，必须主动停止并输出单条清晰命令供用户本地手动执行。

### 2. 零 CLI 探针熔断规约（Zero CLI Probing Interlock）
- 严禁调用 `python3 -c "..."` 探测任何文件长度、行宽、排版或内容！
- 严禁调用 `git status` / `git diff` 探测工作区状态（改动范围与状态由 Agent 上下文精准感知）！
- 探查文件内容 $\to$ **100% 走 `view_file`**；
- 检索关键词、正则、锚点、水印 $\to$ **100% 走 `grep_search`**；
- 局部微调与段落修正 $\to$ **100% 走 `replace_file_content`**。

---

## 五、 破坏性命令守卫与安全避让（DCG 防御）

1. **高危 Shell 指令绝对封禁**：
   严禁在自动化脚本或命令行中使用高危破坏性 Shell 指令（如 `rm -rf`、`kill -9`、带递归参数的强制删除命令），防止触发 IDE 的 Destructive Command Guard（DCG）强拦截弹窗。
2. **命令行内联代码静态拦截警示**：
   严禁在命令行中使用内联代码（如 `python3 -c "import shutil; shutil.rmtree(...)"` 或 `os.rmdir`）执行删除，此类语法模式会被 DCG 静态分析直接识别并阻断；所有文件与缓存清理必须固化在工程 `.py` 脚本文件内部（如 `python3 scripts/clean.py`）安全执行，或通过 `.gitignore` 静默忽略。

---

## 六、 批处理脚本强制内嵌 Python 防御模板

所有由 Agent 生成并执行的批处理脚本，顶部必须强制内嵌以下防御守卫逻辑：

```python
import os
import sys
from pathlib import Path

# 1. 动态锚定工作区根目录（适配真实环境，不写死硬编码，兼容多台机器）
def get_workspace_root() -> Path:
    current = Path(__file__).resolve().parent
    for p in [current] + list(current.parents):
        if (p / "AGENTS.md").exists():
            return p
    return current.parent

WORKSPACE_ROOT = get_workspace_root()

# 2. 强行重定向系统临时目录环境变量，物理拦截第三方库越界写入
TMP_DIR = WORKSPACE_ROOT / ".tmp_pipeline"
TMP_DIR.mkdir(parents=True, exist_ok=True)
os.environ["TMPDIR"] = str(TMP_DIR)
os.environ["TEMP"] = str(TMP_DIR)
os.environ["TMP"] = str(TMP_DIR)

# 3. 物理路径安全守卫 (Guard Assertion)
def guard_path(p: Path | str) -> Path:
    resolved_path = Path(p).resolve()
    ws_resolved = WORKSPACE_ROOT.resolve()
    if not str(resolved_path).startswith(str(ws_resolved)):
        raise RuntimeError(
            f"[FATAL SECURITY ESCALATION] 越界物理路径禁止访问: {resolved_path}\n"
            f"所有读写必须 100% 局限在工作区内部: {ws_resolved}"
        )
    return resolved_path

# 示例: 所有的读写必须经过 guard_path 校验
# guard_path(TMP_DIR / "temp_cache.json").write_text(...)
```

---

## 七、 人工交互绝对 0 弹窗服务等级协议（0-Popup SLA）

1. **查阅、检索、微调、创建**：100% 走原生工具，**全程 0 弹窗**；
2. **二进制解析与重计算**：必须整合为单一流水线脚本，在受控沙箱内单进程闭环运行，**全程 0 弹窗**；
3. **杜绝内部纠结与过程碎片外溢**：严禁把逐步探测与反复重试暴露给用户，所有中间环节自检全部在内存与原生工具沙箱中静默完成，实现真正的无感交付与自主闭环。
