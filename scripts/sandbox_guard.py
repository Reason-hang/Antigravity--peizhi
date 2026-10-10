"""应用层路径检查与显式临时目录；不替代宿主沙箱，不承诺任意任务零弹窗。"""
from __future__ import annotations

import os
import re
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
    raise RuntimeError('没有找到 AGENTS.md，请显式确定工作区根目录')

WORKSPACE_ROOT = get_workspace_root()

def setup_workspace_tmpdir(task_id: str = "pipeline") -> Path:
    """先校验，再创建。调用 tempfile API 时仍须显式传 dir=tmp_dir。"""
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,80}', task_id):
        raise ValueError('task_id 仅允许字母、数字、下划线和连字符')
    tmp_dir = guard_path(WORKSPACE_ROOT / f".tmp_{task_id}")
    tmp_dir.mkdir(parents=True, exist_ok=True)
    os.environ["TMPDIR"] = str(tmp_dir)
    os.environ["TEMP"] = str(tmp_dir)
    os.environ["TMP"] = str(tmp_dir)
    return tmp_dir

def guard_path(path_to_check: Path | str, root: Path | str | None = None) -> Path:
    """检查真实目录包含关系；拒绝根目录、符号链接目标与越界路径。"""
    ws_resolved = Path(root or WORKSPACE_ROOT).expanduser().resolve()
    raw = Path(path_to_check).expanduser()
    raw = raw if raw.is_absolute() else ws_resolved / raw
    resolved = raw.resolve()
    if raw.is_symlink() or resolved == ws_resolved or not resolved.is_relative_to(ws_resolved):
        raise RuntimeError(
            f"[FATAL SECURITY ESCALATION] 越界路径禁止访问: {resolved}\n"
            f"目标必须位于工作区内部: {ws_resolved}"
        )
    return resolved

if __name__ == "__main__":
    tmp = setup_workspace_tmpdir("test_guard")
    print(f"[Sandbox Guard] 受信工作区根目录: {WORKSPACE_ROOT}")
    print(f"[Sandbox Guard] 内部受控临时目录: {tmp}")
    print(f"[Sandbox Guard] 环境变量 TMPDIR 重定向至: {os.environ.get('TMPDIR')}")
    assert guard_path(tmp / "test.txt")
    print("[Sandbox Guard] 应用层路径检查案例通过。")
