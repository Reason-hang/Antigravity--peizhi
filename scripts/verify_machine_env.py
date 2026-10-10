"""核验独立 Hook 配置与决策，不把机器自检等同于应用或双机验收。"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import plistlib
import shlex
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NAME = 'intelligent-safety-gate'

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def load(path):
    spec = importlib.util.spec_from_file_location('machine_gate', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def verify(workspace, home, source_only=False):
    report = {'checked_at_utc': datetime.now(timezone.utc).isoformat(),
              'workspace': str(workspace), 'checks': [], 'cases': [],
              'application_ui': '未验证', 'two_restarts': '未验证', 'other_machine': '未验证'}
    def check(name, passed, detail=''):
        report['checks'].append({'name': name, 'passed': bool(passed), 'detail': detail})
    base = ROOT / 'scripts' if source_only else home / '.gemini/config/scripts'
    manifest = json.loads((ROOT / 'scripts/gate_manifest.json').read_text())
    report['policy_version'] = manifest['version']
    report['policy_hashes'] = manifest['files']
    for name, expected in manifest['files'].items():
        path = base / name
        check(name, path.is_file() and not path.is_symlink() and sha(path) == expected)
    if not source_only:
        hook_path = home / '.gemini/config/hooks.json'
        hooks = json.loads(hook_path.read_text())
        definition = hooks.get(NAME, {})
        check('全局 Hook 已启用', definition.get('enabled', True) and bool(definition.get('PreToolUse')))
        for event, phase in [('PreToolUse', 'pre'), ('PostToolUse', 'post')]:
            groups = definition.get(event, [])
            commands = [h.get('command', '') for group in groups for h in group.get('hooks', [])]
            expected_path = str(base / 'security_gate.py')
            check(event, len(commands) == 1 and len(shlex.split(commands[0])) == 4 and
                  shlex.split(commands[0])[1:] == ['-I', expected_path, phase])
        report['hooks_sha256'] = sha(hook_path)
        for name in ('AGENTS.md', '.agents/rules/zero_popup_interlock.md', 'scripts/sandbox_guard.py'):
            path = workspace / name
            check('工作区 ' + name, path.is_file() and sha(path) == sha(ROOT / name))
    check('工作区存在', workspace.is_dir())
    if not all(c['passed'] for c in report['checks']):
        report['status'] = 'failed'
        return report
    gate = load(base / 'security_gate.py')
    with tempfile.TemporaryDirectory(prefix='.tmp_gate_check_', dir=workspace) as tmp:
        area = Path(tmp).resolve()
        original = area / 'user.txt'
        original.write_text('必须保留')
        cid = '00000000-0000-4000-8000-000000000001'
        payload = {'conversationId': cid, 'workspacePaths': [str(area)],
                   'toolCall': {'name': 'run_command', 'args': {'Cwd': str(area), 'CommandLine': 'pwd'}}}
        cases = [
            ('只读目录', 'pwd', 'allow'),
            ('字符串替换', 'python3 -c "text=\'ab\'; print(text.replace(\'a\',\'b\'))"', 'allow'),
            ('丢弃标准错误', 'python3 -c "import sys; print(sys.executable)" && ls -d /Applications/*[Cc]alibre* 2>/dev/null || true', 'allow'),
            ('真实删除', 'rm -rf user.txt', 'force_ask'),
            ('脚本带参数删除', 'python3 -B danger.py --flag', 'force_ask'),
            ('受保护配置', 'cat .ssh/id_rsa', 'force_ask'),
            ('用户文件覆盖', 'echo changed > user.txt', 'force_ask'),
            ('动态执行', 'python3 -c "eval(\'1\')"', 'force_ask'),
        ]
        (area / 'danger.py').write_text("import shutil\nshutil.rmtree('user.txt')")
        for label, command, expected in cases:
            payload['toolCall'] = {'name': 'run_command', 'args': {'Cwd': str(area), 'CommandLine': command}}
            result = gate.Gate(payload, state_dir=area / 'state').evaluate()
            report['cases'].append({'name': label, 'expected': expected, **result,
                                    'passed': result['decision'] == expected})
        for app in ('antigravity', 'antigravity-ide', 'antigravity-cli'):
            artifact = Path.home() / '.gemini' / app / 'brain' / cid
            sample = {**payload, 'artifactDirectoryPath': str(artifact),
                      'toolCall': {'name': 'write_to_file', 'args': {'TargetFile': str(artifact / 'task.md'), 'CodeContent': 'fixture'}}}
            # 只评估 Hook，不实际创建宿主 Artifact。
            result = gate.Gate(sample, state_dir=area / 'state').evaluate()
            report['cases'].append({'name': app + ' Artifact 适配', 'expected': 'allow', **result, 'passed': result['decision'] == 'allow'})
        outside = area.parent / (area.name + '-outside.txt')
        sample = {**payload, 'toolCall': {'name': 'write_to_file', 'args': {'TargetFile': str(outside), 'CodeContent': 'fixture'}}}
        result = gate.Gate(sample, state_dir=area / 'state').evaluate()
        report['cases'].append({'name': '越界写入', 'expected': 'force_ask', **result, 'passed': result['decision'] == 'force_ask'})
        payload['toolCall'] = {'name': 'run_command', 'args': {'Cwd': str(area), 'CommandLine': 'pwd'}}
        result = gate.Gate(payload, state_dir=area / 'state', dcg=area / 'missing-checker').evaluate()
        report['cases'].append({'name': '检查器缺失', 'expected': 'force_ask', **result, 'passed': result['decision'] == 'force_ask'})
        check('候选高危调用无副作用', original.read_text() == '必须保留' and not outside.exists())
    report['apps'] = {}
    for app in ('Antigravity', 'Antigravity IDE'):
        path = Path('/Applications') / (app + '.app/Contents/Info.plist')
        if path.is_file():
            report['apps'][app] = plistlib.loads(path.read_bytes()).get('CFBundleShortVersionString')
    report['status'] = 'passed' if all(c['passed'] for c in report['checks'] + report['cases']) else 'failed'
    report['scope'] = '源码决策自检' if source_only else '配置落盘与独立 Hook 决策自检；不证明应用实际加载'
    return report

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', type=Path, default=ROOT)
    parser.add_argument('--home', type=Path, default=Path.home())
    parser.add_argument('--source-only', action='store_true')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    try:
        result = verify(args.workspace.expanduser().resolve(), args.home.expanduser().resolve(), args.source_only)
    except Exception as error:
        result = {'status': 'failed', 'error': str(error)}
    text = json.dumps(result, ensure_ascii=False, indent=2) + '\n'
    if args.output:
        args.output.write_text(text)
    print(text)
    sys.exit(0 if result['status'] == 'passed' else 1)
