"""迁移、部署和回退统一 Hook；保留无关设置，不同步凭据、会话与授权缓存。"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import shlex
import sys
import tempfile
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NAME = 'intelligent-safety-gate'
SOURCE = ROOT / 'scripts'
GATE_FILES = ['security_gate.py', 'python_check.py', 'scoped_text_job.py', 'gate_manifest.json']
PROJECT_FILES = ['AGENTS.md', '.agents/rules/zero_popup_interlock.md',
                 'scripts/sandbox_guard.py', 'scripts/verify_machine_env.py',
                 'scripts/manage_gate.py', 'scripts/update_gate_manifest.py',
                 'scripts/security_gate.py', 'scripts/python_check.py',
                 'scripts/scoped_text_job.py', 'scripts/gate_manifest.json', 'README.md',
                 'ebook-to-markdown-pipeline.skill']


def sha(data):
    return hashlib.sha256(data).hexdigest()


def safe_parent(path):
    for parent in [path, *path.parents]:
        if parent.is_symlink():
            raise ValueError(f'部署目标存在符号链接：{parent}')


def write(path, data, mode=0o600):
    safe_parent(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temp = tempfile.mkstemp(prefix='.gate-install-', dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def encoded(data):
    return (json.dumps(data, ensure_ascii=False, indent=2) + '\n').encode()


def plan(home, workspace, interpreter):
    home, workspace = home.expanduser().absolute(), workspace.expanduser().absolute()
    safe_parent(home)
    safe_parent(workspace)
    if not workspace.is_dir() or workspace == home:
        raise ValueError('工作区必须是独立且存在的目录')
    config = home / '.gemini/config'
    destination = config / 'scripts'
    hooks_path = config / 'hooks.json'
    safe_parent(hooks_path)
    old = json.loads(hooks_path.read_text()) if hooks_path.exists() else {}
    if not isinstance(old, dict):
        raise ValueError('hooks.json 格式无效')
    hooks = json.loads(json.dumps(old))
    legacy = hooks.get('intelligent-safety-gate')
    if legacy and legacy.get('enabled', True):
        commands = [item.get('command', '') for event in ('PreToolUse', 'PostToolUse')
                    for group in legacy.get(event, []) for item in group.get('hooks', [])]
        expected = str(config / 'scripts/security_gate.py')
        if not commands or not all(expected in shlex.split(cmd) for cmd in commands):
            raise ValueError('同名旧 Hook 不是已诊断的实现，拒绝自动禁用')
    def handler(matcher, phase):
        command = f'{shlex.quote(str(interpreter))} -I {shlex.quote(str(destination / "security_gate.py"))} {phase}'
        return [{'matcher': matcher, 'hooks': [{'type': 'command', 'command': command, 'timeout': 8}]}]
    hooks[NAME] = {
        'enabled': True,
        'PreToolUse': handler('run_command|write_to_file|replace_file_content|multi_replace_file_content|manage_task|ask_permission', 'pre'),
        'PostToolUse': handler('write_to_file|replace_file_content|multi_replace_file_content', 'post'),
    }
    manifest = json.loads((SOURCE / 'gate_manifest.json').read_text())
    if set(manifest.get('files', {})) != set(GATE_FILES) - {'gate_manifest.json'}:
        raise ValueError('Hook 内容清单不完整')
    for name, expected in manifest['files'].items():
        if (SOURCE / name).is_symlink() or sha((SOURCE / name).read_bytes()) != expected:
            raise ValueError('Hook 哈希不一致，请先更新内容清单')
    files = {destination / name: (SOURCE / name).read_bytes() for name in GATE_FILES}
    for name in PROJECT_FILES:
        files[workspace / name] = (ROOT / name).read_bytes()
    with zipfile.ZipFile(ROOT / 'ebook-to-markdown-pipeline.skill') as package:
        for info in package.infolist():
            relative = Path(info.filename)
            if relative.is_absolute() or '..' in relative.parts or relative.parts[0] != 'ebook-to-markdown-pipeline' or info.file_size > 1048576:
                raise ValueError('技能包存在无效路径或过大成员')
            if not info.is_dir():
                files[workspace / '.agents/skills' / relative] = package.read(info)
    ignore = workspace / '.gitignore'
    text = ignore.read_text() if ignore.exists() else ''
    for line in (ROOT / '.gitignore').read_text().splitlines():
        if line and not line.startswith('#') and line not in text.splitlines():
            text += ('\n' if text and not text.endswith('\n') else '') + line + '\n'
    files[ignore] = text.encode()
    # 代码就绪后，最后切换有效 Hook。
    files[hooks_path] = encoded(hooks)
    for path in files:
        safe_parent(path)
    return files, hooks_path, old, hooks


def install(home, workspace, interpreter):
    files, hooks_path, old, hooks = plan(home, workspace, interpreter)
    changes = {p: data for p, data in files.items() if not p.is_file() or p.read_bytes() != data}
    if not changes:
        return {'status': 'already_installed', 'changed_files': 0}
    backup = home / '.gemini/config/backups' / NAME / (datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8])
    safe_parent(backup)
    backup.mkdir(parents=True, mode=0o700)
    entries = []
    for index, (path, data) in enumerate(changes.items()):
        existed = path.exists()
        original = path.read_bytes() if existed else None
        if original is not None:
            write(backup / f'{index}.original', original)
        entries.append({'path': str(path), 'original': f'{index}.original' if existed else None,
                        'before_sha256': sha(original) if original is not None else None,
                        'after_sha256': sha(data), 'mode': (path.stat().st_mode & 0o777) if existed else 0o600})
    manifest = {'version': 1, 'home': str(home), 'workspace': str(workspace),
                'hook_path': str(hooks_path), 'before_hooks': old, 'after_hooks': hooks,
                'files': entries, 'state': 'prepared'}
    write(backup / 'manifest.json', encoded(manifest))
    applied = []
    try:
        for entry in entries:
            path = Path(entry['path'])
            write(path, changes[path], entry['mode'])
            applied.append(entry)
        manifest['state'] = 'installed'
        write(backup / 'manifest.json', encoded(manifest))
    except Exception:
        for entry in reversed(applied):
            path = Path(entry['path'])
            if path.is_file() and sha(path.read_bytes()) == entry['after_sha256']:
                if entry['original']:
                    write(path, (backup / entry['original']).read_bytes(), entry['mode'])
                else:
                    path.unlink()
        manifest['state'] = 'failed_rolled_back'
        write(backup / 'manifest.json', encoded(manifest))
        raise
    return {'status': 'installed', 'changed_files': len(entries), 'backup_manifest': str(backup / 'manifest.json')}


def restore(manifest_path):
    safe_parent(manifest_path)
    manifest = json.loads(manifest_path.read_text())
    home, workspace = Path(manifest['home']), Path(manifest['workspace'])
    config = home / '.gemini/config'
    safe_parent(home)
    safe_parent(workspace)
    hook_path = Path(manifest['hook_path'])
    if hook_path != config / 'hooks.json' or manifest['state'] != 'installed':
        raise ValueError('不是可恢复的安装记录')
    current = json.loads(hook_path.read_text())
    changed_keys = {k for k in set(manifest['before_hooks']) | set(manifest['after_hooks'])
                    if manifest['before_hooks'].get(k) != manifest['after_hooks'].get(k)}
    for key in changed_keys:
        if current.get(key) != manifest['after_hooks'].get(key):
            raise ValueError('安装后相关 Hook 已修改，拒绝覆盖')
    for entry in manifest['files']:
        path = Path(entry['path'])
        safe_parent(path)
        if not (path.is_relative_to(config) or path.is_relative_to(workspace)):
            raise ValueError('恢复目标超出安装范围')
        if path != hook_path and (not path.is_file() or sha(path.read_bytes()) != entry['after_sha256']):
            raise ValueError(f'安装后文件已修改，拒绝覆盖：{path}')
        if entry['original']:
            original = manifest_path.parent / entry['original']
            if original.parent != manifest_path.parent or sha(original.read_bytes()) != entry['before_sha256']:
                raise ValueError('备份校验失败')
    for key in changed_keys:
        if key in manifest['before_hooks']:
            current[key] = manifest['before_hooks'][key]
        else:
            current.pop(key, None)
    hook_entry = next((e for e in manifest['files'] if Path(e['path']) == hook_path), None)
    if hook_entry and not hook_entry['original'] and not current:
        hook_path.unlink()
    elif hook_entry and hook_entry['original'] and current == manifest['before_hooks']:
        write(hook_path, (manifest_path.parent / hook_entry['original']).read_bytes(), hook_entry['mode'])
    else:
        write(hook_path, encoded(current))
    for entry in reversed(manifest['files']):
        path = Path(entry['path'])
        if path == hook_path:
            continue
        if entry['original']:
            write(path, (manifest_path.parent / entry['original']).read_bytes(), entry['mode'])
        else:
            path.unlink()
    manifest['state'] = 'restored'
    write(manifest_path, encoded(manifest))
    return {'status': 'restored', 'unrelated_hooks_preserved': True}


def main():
    if sys.version_info < (3, 10):
        raise SystemExit('需要 Python 3.10+；没有修改任何配置')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['plan', 'install', 'restore'])
    parser.add_argument('--workspace', type=Path, default=ROOT)
    parser.add_argument('--home', type=Path, default=Path.home(), help='隔离测试可指定模拟主目录')
    parser.add_argument('--manifest', type=Path)
    args = parser.parse_args()
    home, workspace = args.home.expanduser().absolute(), args.workspace.expanduser().absolute()
    if args.action == 'restore':
        if not args.manifest:
            parser.error('restore 需要 --manifest')
        result = restore(args.manifest.absolute())
    elif args.action == 'install':
        result = install(home, workspace, Path(sys.executable).resolve())
    else:
        files, _, _, _ = plan(home, workspace, Path(sys.executable).resolve())
        result = {'status': 'plan', 'targets': [str(p) for p in files],
                  'changed_files': sum(not p.is_file() or p.read_bytes() != data for p, data in files.items())}
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
