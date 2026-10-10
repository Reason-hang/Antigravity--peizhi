"""固定文本处理入口。只处理 JSON 指定的文本，不运行代码；输出先备份再原子替换。"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
import uuid
from pathlib import Path

PROTECTED = {'.git', '.agents', '.codex', '.gemini', '.ssh', '.aws'}
NAMES = {'AGENTS.md', 'GEMINI.md', '.env', '.zshrc', '.zprofile'}


def guarded(raw, root):
    p = Path(raw).expanduser()
    p = p if p.is_absolute() else root / p
    resolved = p.resolve()
    if resolved == root or not resolved.is_relative_to(root) or p.is_symlink():
        raise ValueError('目标越界、根目录或符号链接')
    if PROTECTED.intersection(p.parts) or PROTECTED.intersection(resolved.parts) or resolved.name in NAMES or resolved.name.startswith('.env.'):
        raise ValueError('受保护配置禁止作为任务输入输出')
    return resolved


def read_job(job_path, root):
    job_path = guarded(job_path, root)
    if job_path.stat().st_size > 1048576:
        raise ValueError('任务描述过大')
    job = json.loads(job_path.read_text())
    if not isinstance(job, dict) or set(job) - {'input', 'output', 'replacements', 'overwrite'}:
        raise ValueError('任务字段无效')
    if not all(isinstance(job.get(k), str) for k in ('input', 'output')):
        raise ValueError('缺少输入输出路径')
    source, output = guarded(job['input'], root), guarded(job['output'], root)
    if source == output or not source.is_file() or (output.exists() and not output.is_file()):
        raise ValueError('输入输出相同、输入缺失或输出不是文件')
    if source.stat().st_size > 134217728:
        raise ValueError('仅支持 128 MiB 以内的 UTF-8 文本')
    pairs = job.get('replacements', [])
    if not isinstance(pairs, list) or len(pairs) > 1000 or not all(isinstance(p, list) and len(p) == 2 and all(isinstance(s, str) for s in p) and p[0] for p in pairs):
        raise ValueError('替换必须是非空源字符串与目标字符串的列表')
    if not isinstance(job.get('overwrite', False), bool):
        raise ValueError('overwrite 必须为布尔值')
    if output.exists() and not job.get('overwrite', False):
        raise ValueError('输出已存在；需明确指定 overwrite，执行前仍接受权限审查')
    return job, source, output


def run(job_path, root):
    root = root.expanduser().resolve()
    if not root.is_dir():
        raise ValueError('工作区不存在')
    job, source, output = read_job(job_path, root)
    original = source.read_bytes()
    text = original.decode('utf-8')
    for old, new in job.get('replacements', []):
        text = text.replace(old, new)
    data = text.encode('utf-8')
    if len(data) > 268435456:
        raise ValueError('输出超过 256 MiB 限制')
    output.parent.mkdir(parents=True, exist_ok=True)
    # 再检查一次实际路径，避免父目录变动；这仍不能替代原生沙箱。
    output = guarded(str(output), root)
    backup = None
    if output.exists():
        backup_dir = guarded('.pipeline_backups', root)
        backup_dir.mkdir(mode=0o700, exist_ok=True)
        backup = guarded(str(backup_dir / (uuid.uuid4().hex + '.bak')), root)
        fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as f:
            f.write(output.read_bytes())
            f.flush()
            os.fsync(f.fileno())
    tmp_dir = guarded('.tmp_pipeline', root)
    tmp_dir.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix='text-job-', dir=tmp_dir)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        # 新文件采用硬链接排他创建，拒绝覆盖执行期间出现的用户文件。
        if not job.get('overwrite', False):
            os.link(temp, output)
        else:
            os.replace(temp, output)
        result = {'input_sha256': hashlib.sha256(original).hexdigest(),
                  'output_sha256': hashlib.sha256(data).hexdigest(),
                  'output': str(output), 'backup': str(backup) if backup else None}
        print(json.dumps(result, ensure_ascii=False))
        return result
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', required=True, type=Path)
    parser.add_argument('--job', required=True, type=Path)
    args = parser.parse_args()
    run(args.job, args.workspace)
