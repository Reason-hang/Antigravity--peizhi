"""直接调用已安装 Hook 的正式入口；不证明宿主已加载，不执行危险候选。"""
from __future__ import annotations
import argparse
import json
import shlex
import subprocess
import tempfile
import uuid
from pathlib import Path

def probe(workspace):
    home = Path.home()
    hooks = json.loads((home / '.gemini/config/hooks.json').read_text())['intelligent-safety-gate']
    entry = {event: shlex.split(hooks[event][0]['hooks'][0]['command']) for event in ['PreToolUse', 'PostToolUse']}
    cid = str(uuid.uuid4())
    cases = []
    with tempfile.TemporaryDirectory(prefix='.tmp_installed_gate_', dir=workspace) as tmp:
        area = Path(tmp).resolve()
        counter = 0
        def invoke(call, expected, phase='PreToolUse'):
            nonlocal counter
            payload = {'conversationId': cid, 'stepIdx': counter, 'workspacePaths': [str(area)], 'toolCall': call}
            counter += 1
            result = subprocess.run(entry[phase], input=json.dumps(payload), text=True, capture_output=True, timeout=8)
            if result.returncode:
                raise RuntimeError(result.stderr)
            output = json.loads(result.stdout)
            passed = output == {} if phase == 'PostToolUse' else output.get('decision') == expected
            cases.append({'tool': call['name'], 'phase': phase, 'expected': expected, 'passed': passed, **output})
        for command, expected in [('pwd', 'allow'), ('python3 -c "s=\'abc\'; print(s.replace(\'a\',\'b\'))"', 'allow'),
                                  ('rm -rf preserve.txt', 'force_ask')]:
            invoke({'name': 'run_command', 'args': {'Cwd': str(area), 'CommandLine': command}}, expected)
        path = area / 'preserve.txt'
        call = {'name': 'write_to_file', 'args': {'TargetFile': str(path), 'CodeContent': 'original'}}
        invoke(call, 'allow')
        path.write_text('original')
        invoke(call, None, 'PostToolUse')
        call['args']['CodeContent'] = 'updated'
        invoke(call, 'allow')
        path.write_text('user edit')
        invoke(call, 'force_ask')
        if path.read_text() != 'user edit':
            raise RuntimeError('候选评估改变了测试文件')
    audit = home / '.gemini/config/safety_gate_state/audit.jsonl'
    records = [json.loads(s) for s in audit.read_text().splitlines() if json.loads(s).get('conversationId') == cid]
    return {'status': 'passed' if all(c['passed'] for c in cases) and len(records) == len(cases) else 'failed',
            'scope': '直接进程调用已安装 Hook；非应用 UI 验收', 'conversationId': cid,
            'cases': cases, 'audit_records': len(records), 'audit_versions': sorted({r['version'] for r in records})}

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = probe(args.workspace.expanduser().resolve())
    text = json.dumps(result, ensure_ascii=False, indent=2) + '\n'
    args.output.write_text(text)
    print(text)
    raise SystemExit(0 if result['status'] == 'passed' else 1)
