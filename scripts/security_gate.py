"""Pre/PostToolUse 统一安全策略；仅返回决策，不执行候选命令。"""
from __future__ import annotations

import datetime
import fcntl
import hashlib
import importlib.util
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

VERSION = '3.0.0'
BASE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('scoped_python_check', BASE / 'python_check.py')
python_check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(python_check)
PROTECTED_PARTS = {'.git', '.agents', '.codex', '.gemini', '.ssh', '.aws', '.system_generated'}
PROTECTED_NAMES = {'AGENTS.md', 'GEMINI.md', '.zshrc', '.zprofile', '.bashrc',
                   '.bash_profile', '.profile', '.env', 'id_rsa', 'id_ed25519'}
FILE_TOOLS = {'write_to_file', 'replace_file_content', 'multi_replace_file_content'}
READ_COMMANDS = {'ls', 'rg', 'grep', 'cat', 'head', 'tail', 'wc', 'file', 'stat',
                 'du', 'pwd', 'uname', 'sw_vers', 'which', 'echo', 'printf', 'true'}
HIGH_COMMANDS = {'rm', 'unlink', 'rmdir', 'sudo', 'chmod', 'chown', 'launchctl',
                 'diskutil', 'dd', 'mkfs', 'cp', 'mv', 'tee', 'truncate', 'ln', 'install'}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def atomic_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temp = tempfile.mkstemp(prefix='.state-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


class Gate:
    def __init__(self, payload, state_dir=None, dcg=None):
        if not isinstance(payload, dict):
            raise ValueError('无效输入')
        self.payload = payload
        self.cid = payload.get('conversationId', '')
        if not re.fullmatch(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}', self.cid):
            raise ValueError('缺少有效会话 ID')
        roots = payload.get('workspacePaths')
        if not isinstance(roots, list) or not roots or not all(isinstance(p, str) and Path(p).is_absolute() and Path(p).is_dir() for p in roots):
            raise ValueError('缺少实际工作区，禁止回退到整个 Documents')
        self.roots = [Path(p).resolve() for p in roots]
        self.artifact = None
        artifact = payload.get('artifactDirectoryPath')
        if artifact:
            if not isinstance(artifact, str) or not Path(artifact).is_absolute():
                raise ValueError('Artifact 路径无效')
            expected = [Path.home() / '.gemini' / app / 'brain' / self.cid
                        for app in ('antigravity', 'antigravity-ide', 'antigravity-cli')]
            if not any(Path(artifact) == p and Path(artifact).resolve() == p for p in expected):
                raise ValueError('Artifact 不属于当前宿主会话，或有符号链接')
            self.artifact = Path(artifact)
        call = payload.get('toolCall')
        if not isinstance(call, dict) or not isinstance(call.get('args'), dict):
            raise ValueError('缺少 toolCall')
        self.call = call
        self.name, self.args = call.get('name'), call['args']
        self.state_dir = Path(state_dir) if state_dir else BASE.parent / 'safety_gate_state'
        self.state_path = self.state_dir / (self.cid + '.json')
        if self.state_path.is_symlink():
            raise ValueError('状态文件是符号链接')
        self.state = json.loads(self.state_path.read_text()) if self.state_path.exists() else {'owned': {}, 'pending': {}}
        if not isinstance(self.state.get('owned'), dict) or not isinstance(self.state.get('pending'), dict):
            raise ValueError('所有权记录损坏')
        self.dcg = str(dcg or Path.home() / '.local/bin/dcg')

    def inside(self, path):
        p = Path(path).resolve()
        return any(p.is_relative_to(r) and p != r for r in self.roots) or bool(self.artifact and p.is_relative_to(self.artifact))

    def protected(self, path):
        raw, p = Path(path), Path(path).resolve()
        if self.artifact and raw.is_relative_to(self.artifact) and p.is_relative_to(self.artifact):
            return p.name in PROTECTED_NAMES or p.name.startswith('.env') or bool(({'.git', '.ssh', '.agents', '.codex', '.aws', '.system_generated'}).intersection(p.relative_to(self.artifact).parts))
        return bool(PROTECTED_PARTS.intersection(raw.parts) or PROTECTED_PARTS.intersection(p.parts)) or p.name in PROTECTED_NAMES or p.name.startswith('.env.')

    def result(self, decision, code, reason):
        return {'decision': decision, 'reason': f'[{code}] {reason}'}

    def ask(self, code, reason):
        return self.result('force_ask', code, reason)

    def allow(self, code, reason):
        return self.result('allow', code, reason)

    def token(self):
        return digest(json.dumps({'name': self.name, 'args': self.args}, sort_keys=True).encode())

    def owns(self, path):
        return path.is_file() and not path.is_symlink() and self.state['owned'].get(str(path.resolve())) == digest(path.read_bytes())

    def file(self):
        path = self.args.get('TargetFile')
        if not isinstance(path, str) or not Path(path).is_absolute():
            return self.ask('INPUT', '写入目标必须是绝对路径')
        path = Path(path)
        if not self.inside(path) or self.protected(path) or path.is_symlink():
            return self.ask('BOUNDARY', '写入越界、符号链接或受保护配置')
        canonical = str(path.resolve())
        if self.name == 'write_to_file' and path.exists():
            owned_hash = self.state['owned'].get(canonical)
            artifact = self.artifact and path.resolve().is_relative_to(self.artifact)
            if not artifact and (not path.is_file() or not owned_hash or digest(path.read_bytes()) != owned_hash):
                return self.ask('OVERWRITE', '整文件覆盖不是本会话所有，或内容已有其他改动')
        # 只在完成事件确认成功、内容哈希吻合后记录所有权。
        self.state['pending'][self.token()] = {
            'path': canonical, 'new': not path.exists(),
            'owned': self.owns(path),
            'expected': digest(self.args['CodeContent'].encode()) if self.name == 'write_to_file' and isinstance(self.args.get('CodeContent'), str) else None,
        }
        atomic_json(self.state_path, self.state)
        return self.allow('WORKSPACE_EDIT', '当前授权范围内新建、局部编辑或本会话文件更新')

    def post(self):
        pending = self.state['pending'].pop(self.token(), None)
        if pending and not self.payload.get('error'):
            path = Path(pending['path'])
            if path.is_file() and not path.is_symlink() and self.inside(path) and not self.protected(path):
                actual = digest(path.read_bytes())
                if (pending['new'] and pending['expected'] == actual) or (pending['owned'] and (pending['expected'] is None or pending['expected'] == actual)):
                    self.state['owned'][str(path)] = actual
        atomic_json(self.state_path, self.state)
        return {}

    def python(self, words, cwd):
        index = 1
        while index < len(words) and words[index] in {'-B', '-I', '-u', '-E', '-s', '-O', '-OO'}:
            index += 1
        if '-I' not in words[1:index] and (
            os.environ.get('PYTHONPATH') or os.environ.get('PYTHONHOME') or
            any((cwd / name).exists() for name in ('sitecustomize.py', 'usercustomize.py', 'sitecustomize', 'usercustomize'))
        ):
            return 'Python 启动环境可能加载未检查代码，请使用 -I'
        if index >= len(words):
            return '缺少 Python 脚本'
        script = None
        if words[index] == '-c':
            if index + 1 >= len(words):
                return '缺少 Python 内容'
            source = words[index + 1]
        elif words[index].startswith('-'):
            return '未支持的 Python 模块、标准输入或解释器选项'
        else:
            script = Path(words[index]).expanduser()
            script = (script if script.is_absolute() else cwd / script).resolve()
            if script == BASE / 'scoped_text_job.py':
                if '-I' not in words[1:index]:
                    return '固定入口必须使用 Python -I，隔离项目导入路径'
                return self.trusted_job(words[index + 1:], cwd)
            if not self.inside(script) or self.protected(script):
                return '脚本越界或位于配置目录；使用安装的受控入口'
            if not script.is_file() or script.stat().st_size > 1048576:
                return '脚本缺失或超过检查上限'
            source = script.read_text()
        return python_check.check_python(source, cwd, script, self.inside, self.protected, self.owns)

    def trusted_job(self, args, cwd):
        if len(args) != 4 or args[0] != '--workspace' or args[2] != '--job' or Path(args[1]).resolve() != cwd:
            return '受控入口必须使用当前 Cwd 和明确的 --workspace/--job'
        manifest = json.loads((BASE / 'gate_manifest.json').read_text())
        required = {'security_gate.py', 'python_check.py', 'scoped_text_job.py'}
        if set(manifest.get('files', {})) != required:
            return 'Hook 内容清单不完整'
        for name, expected in manifest['files'].items():
            path = BASE / name
            if not path.is_file() or path.is_symlink() or digest(path.read_bytes()) != expected:
                return '受控 Hook 内容哈希不一致'
        path = BASE / 'scoped_text_job.py'
        spec = importlib.util.spec_from_file_location('scoped_text_job', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        try:
            _, _, output = module.read_job(args[3], cwd)
            if output.exists():
                return '受控任务将覆盖已有交付物，仍需确认'
        except (OSError, ValueError, TypeError):
            return '受控任务描述无效或路径越界'
        return None

    def command(self):
        cmd, raw_cwd = self.args.get('CommandLine'), self.args.get('Cwd')
        if not isinstance(cmd, str) or not cmd.strip() or len(cmd) > 131072 or not isinstance(raw_cwd, str) or not Path(raw_cwd).is_dir():
            return self.ask('INPUT', '命令或工作目录无效')
        cwd = Path(raw_cwd).resolve()
        if not (cwd in self.roots or self.inside(cwd)) or self.protected(cwd):
            return self.ask('BOUNDARY', '工作目录越界或属于配置目录')
        if any(s in cmd for s in ('$(', '`', '<(', '>(', '${')):
            return self.ask('DYNAMIC', '动态 Shell 替换需要审查')
        try:
            lex = shlex.shlex(cmd, posix=True, punctuation_chars=';&|<>\n')
            lex.whitespace = ' \t\r'
            lex.whitespace_split = True
            parts = list(lex)
        except ValueError:
            return self.ask('PARSE', 'Shell 引号或结构无效')
        segments, current = [], []
        i = 0
        while i < len(parts):
            word = parts[i]
            if word in {'>', '>>', '<'}:
                if i + 1 >= len(parts):
                    return self.ask('REDIRECT', '重定向目标缺失')
                destination = parts[i + 1]
                fd = current.pop() if current and current[-1].isdigit() else None
                target = Path(destination).expanduser()
                target = (target if target.is_absolute() else cwd / target).resolve()
                if word != '<' and not (destination == '/dev/null' and fd in {None, '1', '2'}):
                    return self.ask('REDIRECT', '文件重定向需要审查；新文件优先使用原生工具')
                if word == '<' and (not self.inside(target) or self.protected(target)):
                    return self.ask('REDIRECT', '读取重定向越界或涉及配置')
                i += 2
                continue
            if word in {';', '&&', '||', '|', '&', '\n'}:
                if not current or word == '&':
                    return self.ask('PARSE', '空命令或后台结构需要审查')
                segments.append(current)
                current = []
            elif word and all(c in ';&|<>' for c in word):
                return self.ask('REDIRECT', '未支持的 Shell 重定向结构')
            else:
                current.append(word)
            i += 1
        if current:
            segments.append(current)
        if not segments:
            return self.ask('INPUT', '空命令')
        for words in segments:
            exe = Path(words[0]).name
            installed = shutil.which(exe)
            if not installed or any(Path(installed).resolve().is_relative_to(r) for r in self.roots) or (words[0] != exe and (not Path(words[0]).is_absolute() or Path(words[0]).resolve() != Path(installed).resolve())):
                return self.ask('EXECUTABLE', '执行文件不是已安装的入口，或被工作区文件遮蔽')
            if exe in HIGH_COMMANDS:
                return self.ask('DESTRUCTIVE', '删除、覆盖、移动、系统或权限操作')
            if exe in {'sh', 'bash', 'zsh', 'env', 'command', 'eval', 'exec', 'xargs'} or '=' in words[0]:
                return self.ask('WRAPPER', '间接命令执行需要审查')
            trusted_path = str(BASE / 'scoped_text_job.py')
            if any('$' in w or (w != trusted_path and self.protected(Path(w))) for w in words[1:] if w.startswith(('/', '.', '~', '$'))):
                return self.ask('PROTECTED', '涉及配置路径或动态变量')
            if re.fullmatch(r'python(?:3(?:\.\d+)?)?', exe):
                risk = self.python(words, cwd)
                if risk:
                    return self.ask('PYTHON', risk)
            elif exe == 'git':
                if len(words) < 2 or words[1] not in {'status', 'diff', 'log', 'show', 'rev-parse', 'ls-files', 'ls-remote'} or any(w.startswith(('--output', '--ext-diff', '--textconv', '--no-index')) for w in words[2:]):
                    return self.ask('GIT', '仅直接只读 Git 子命令自动批准')
            elif exe not in READ_COMMANDS:
                return self.ask('ENTRYPOINT', '未定义的执行入口需要审查')
            if exe == 'file' and any(w == '--compile' or (w.startswith('-') and not w.startswith('--') and 'C' in w) for w in words[1:]):
                return self.ask('ENTRYPOINT', 'file 编译模式会写文件')
            if exe == 'rg' and any(w.startswith(('--hostname-bin', '--pre')) for w in words[1:]):
                return self.ask('WRAPPER', 'rg 包含外部执行选项')
            if exe in {'rg', 'grep', 'find', 'ls', 'cat', 'head', 'tail', 'stat', 'file', 'du'} and any(w in {'--pre', '--pre-glob', '-exec', '-execdir', '--files-with-matches'} or w.startswith('--pre=') for w in words[1:]):
                return self.ask('WRAPPER', '检索工具包含预处理执行选项')
        try:
            checked = subprocess.run([self.dcg, 'test', '--robot', '--stdin', '--heredoc-scan'],
                                     input=cmd, text=True, capture_output=True, cwd=cwd, timeout=3)
            verdict = json.loads(checked.stdout)
            if not isinstance(verdict, dict) or verdict.get('schema_version') != 1:
                return self.ask('CHECKER_PROTOCOL', 'DCG 协议异常')
            if checked.returncode == 0 and verdict.get('decision') == 'allow':
                return self.allow('SANDBOX', '通过常规操作检查；原生权限与沙箱仍生效')
            return self.ask('DCG', 'DCG 未批准该调用')
        except (OSError, ValueError, subprocess.TimeoutExpired):
            return self.ask('CHECKER_FAILURE', 'DCG 缺失、超时或返回异常')

    def evaluate(self):
        if self.name in FILE_TOOLS:
            return self.file()
        if self.name == 'run_command':
            return self.command()
        if self.name == 'manage_task' and self.args.get('Action') in {'list', 'status'}:
            return self.allow('TASK_READ', '读取任务状态')
        return self.ask('OTHER_TOOL', '权限变更、终端输入或未知操作需要审查')


def main():
    post = len(sys.argv) == 2 and sys.argv[1] == 'post'
    output = {} if post else {'decision': 'force_ask', 'reason': '[GATE_FAILURE] 输入、状态或网关检查异常'}
    try:
        raw = sys.stdin.read(1048577)
        if len(raw) > 1048576:
            raise ValueError('输入过大')
        payload = json.loads(raw)
        cid = payload.get('conversationId', '')
        if not re.fullmatch(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}', cid):
            raise ValueError('会话 ID 无效')
        state = BASE.parent / 'safety_gate_state'
        if state.is_symlink():
            raise ValueError('状态目录是符号链接')
        state.mkdir(parents=True, exist_ok=True, mode=0o700)
        lock_path = state / (cid + '.lock')
        if lock_path.is_symlink():
            raise ValueError('锁文件是符号链接')
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        with os.fdopen(fd, 'r+') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            gate = Gate(payload)
            if gate.state_path.is_symlink():
                raise ValueError('状态文件是符号链接')
            output = gate.post() if post else gate.evaluate()
            record = {'time': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                      'version': VERSION, 'event': 'post' if post else 'pre',
                      'conversationId': gate.cid, 'stepIdx': payload.get('stepIdx'),
                      'call_sha256': gate.token(), **output}
            log = state / 'audit.jsonl'
            if log.is_symlink():
                raise ValueError('审计日志是符号链接')
            fd = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, 'w') as f:
                f.write(json.dumps(record, ensure_ascii=False) + '\n')
    except Exception:
        output = {} if post else {'decision': 'force_ask', 'reason': '[GATE_FAILURE] 输入、状态、审计或网关异常，未自动批准'}
    print(json.dumps(output, ensure_ascii=False))


if __name__ == '__main__':
    main()
