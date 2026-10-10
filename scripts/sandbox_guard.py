"""
Sandbox Guard Module (物理级 0 弹窗安全守卫库)
用于在所有批处理脚本中强行收敛临时目录至工作区内部，并提供物理路径安全断言。
"""

import os
import sys
from pathlib import Path

def get_workspace_root() -> Path:
    """
    动态查找并锁定工作区根目录（以包含 AGENTS.md 或当前项目的根为基准）
    """
    current = Path(__file__).resolve().parent
    for p in [current] + list(current.parents):
        if (p / "AGENTS.md").exists():
            return p
    # 默认兜底为当前文件上级目录
    return current.parent

WORKSPACE_ROOT = get_workspace_root()

def setup_workspace_tmpdir(task_id: str = "pipeline") -> Path:
    """
    在工作区内部创建受控临时目录，并强行重定向系统环境变量，
    彻底物理阻断第三方库向操作系统 /tmp 写入数据引发的沙箱越权弹窗。
    """
    tmp_dir = WORKSPACE_ROOT / f".tmp_{task_id}"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    os.environ["TMPDIR"] = str(tmp_dir)
    os.environ["TEMP"] = str(tmp_dir)
    os.environ["TMP"] = str(tmp_dir)
    return tmp_dir

def guard_path(path_to_check: Path | str) -> Path:
    """
    物理路径断言守卫：
    严格校验目标路径的真实物理规范路径（Canonical Path）是否位于受信工作区内部。
    若越界则直接抛出异常，绝不向系统沙箱外发起读写，从源头杜绝弹窗死锁。
    """
    resolved = Path(path_to_check).resolve()
    ws_resolved = WORKSPACE_ROOT.resolve()
    if not str(resolved).startswith(str(ws_resolved)):
        raise RuntimeError(
            f"[FATAL SECURITY ESCALATION] 越界物理路径禁止访问: {resolved}\n"
            f"所有读写必须 100% 局限在工作区内部: {ws_resolved}"
        )
    return resolved

if __name__ == "__main__":
    tmp = setup_workspace_tmpdir("test_guard")
    print(f"[Sandbox Guard] 受信工作区根目录: {WORKSPACE_ROOT}")
    print(f"[Sandbox Guard] 内部受控临时目录: {tmp}")
    print(f"[Sandbox Guard] 环境变量 TMPDIR 重定向至: {os.environ.get('TMPDIR')}")
    assert guard_path(tmp / "test.txt")
    print("[Sandbox Guard] 自检通过：物理守卫状态正常！")
