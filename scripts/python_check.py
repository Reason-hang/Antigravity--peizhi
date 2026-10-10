"""保守检查数据处理脚本；不是任意 Python 的安全证明。未知写入/反射/依赖均询问。"""
from __future__ import annotations

import ast
from pathlib import Path

SAFE_MODULES = {
    'os', 'sys', 'json', 're', 'struct', 'hashlib', 'html', 'datetime',
    'pathlib', 'collections', 'itertools', 'functools', 'math', 'statistics',
    'typing', 'types', 'unicodedata', 'string', 'csv', 'io', 'shutil',
}
SAFE_CALLS = {
    'print', 'str', 'bytes', 'len', 'int', 'float', 'bool', 'range', 'enumerate',
    'zip', 'sorted', 'min', 'max', 'sum', 'abs', 'round', 'dict', 'list', 'set',
    'tuple', 'bytearray', 'isinstance', 'ord', 'chr',
    'pathlib.Path', 'pathlib.Path.cwd', 'pathlib.Path.home',
    're.sub', 're.subn', 're.search', 're.match', 're.fullmatch', 're.findall',
    're.split', 're.escape', 'json.loads', 'json.dumps', 'html.unescape',
    'struct.unpack', 'struct.unpack_from', 'struct.calcsize',
    'unicodedata.normalize', 'unicodedata.category',
    'os.path.join', 'os.path.abspath', 'os.path.dirname', 'os.path.basename',
    'os.path.exists', 'os.path.isfile', 'os.path.isdir', 'os.getcwd',
}
SAFE_METHODS = {
    'str': {'replace', 'strip', 'lstrip', 'rstrip', 'lower', 'upper', 'split',
            'splitlines', 'join', 'startswith', 'endswith', 'find', 'count', 'encode'},
    'bytes': {'replace', 'strip', 'split', 'find', 'decode'},
    'path': {'resolve', 'absolute', 'expanduser', 'exists', 'is_file', 'is_dir',
             'read_text', 'read_bytes', 'write_text', 'write_bytes', 'touch', 'mkdir', 'open'},
    'file_text': {'read', 'write', 'writelines', 'close'},
    'file_bytes': {'read', 'write', 'writelines', 'close'},
}
DANGEROUS = {
    'remove', 'unlink', 'rmdir', 'rmtree', 'rename', 'renames', 'chmod', 'chown',
    'system', 'popen', 'exec', 'eval', '__import__', 'compile', 'getattr',
    'setattr', 'delattr', 'globals', 'locals', 'vars', 'import_module',
    'run', 'Popen', 'call', 'check_call', 'check_output', 'execfile',
    'copy', 'copy2', 'copyfile', 'copytree', 'move', 'symlink', 'link',
    'kill', 'killpg', 'fork', 'spawn', 'startfile', 'extract', 'extractall',
    'loads_pickle', 'fchmod', 'fchown', 'truncate', 'ftruncate',
    'putenv', 'unsetenv', 'chdir', 'chroot', 'setuid', 'setgid',
}
REFLECTIVE_ATTRIBUTES = {'__dict__', '__class__', '__globals__', '__builtins__',
                         '__subclasses__', '__getattribute__', '__code__'}
WRITE_METHODS = {'write_text', 'write_bytes', 'touch', 'mkdir', 'write', 'writelines'}


def check_python(source: str, cwd: Path, script: Path | None, inside, protected, can_overwrite=lambda p: False) -> str | None:
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError):
        return 'Python 无法解析'
    symbols: dict[str, str] = {}
    shadowed: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.NamedExpr, ast.AugAssign, ast.Lambda)):
            return '动态绑定或闭包需要审查，不能沿用旧类型推断'
        if isinstance(node, ast.Assign) and any(not isinstance(t, ast.Name) for t in node.targets):
            return '解包或间接赋值需要审查'
        if isinstance(node, ast.Attribute) and node.attr in {'environ', 'modules', 'meta_path', 'path_hooks'}:
            return '环境或模块运行时对象需要审查'
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            module = node.module if isinstance(node, ast.ImportFrom) else None
            if isinstance(node, ast.ImportFrom) and (node.level or any(a.name == '*' for a in node.names)):
                return '相对或星号导入需要审查'
            for alias in node.names:
                imported = module or alias.name
                if imported not in SAFE_MODULES and imported != 'os.path':
                    return f'未审定的 Python 依赖：{imported}'
                # 即便名字属于标准库，也不信任项目里同名的模块。
                locations = {cwd, script.parent if script else cwd}
                if any((p / (imported.split('.')[0] + '.py')).exists() or
                       (p / imported.split('.')[0] / '__init__.py').exists() for p in locations):
                    return f'项目模块遮蔽标准库：{imported}'
                key = alias.asname or (alias.name if module else alias.name.split('.')[0])
                symbols[key] = f'{module}.{alias.name}' if module else alias.name
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            shadowed.add(node.id)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            shadowed.add(node.name)
            return '自定义函数、装饰器或类需要单独审查；常规处理使用固定入口'
        if isinstance(node, ast.ClassDef):
            return '自定义类需单独审查，不能据方法名推断副作用'
        if isinstance(node, ast.Attribute) and (node.attr in REFLECTIVE_ATTRIBUTES or node.attr.startswith('__')):
            return 'Python 含反射或运行时修改'
        if isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)):
            return 'Python 修改对象属性，需要审查'
        if isinstance(node, ast.Subscript) and isinstance(node.ctx, (ast.Store, ast.Del)):
            if isinstance(node.value, ast.Attribute) and node.value.attr in {'environ', 'modules'}:
                return 'Python 修改运行时环境，需要审查'
    if shadowed.intersection(symbols) or shadowed.intersection({'str', 'bytes', 'open', 'Path'}):
        return '模块或关键内置函数被重新绑定'

    def qualified(node):
        if isinstance(node, ast.Name):
            return symbols.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            return qualified(node.value) + '.' + node.attr
        return ''

    # 值只记录明确的字符串、字节、路径或已打开文件；不信任类型注解。
    def value(node, env):
        if isinstance(node, ast.Constant):
            if isinstance(node.value, str):
                return ('str', node.value)
            if isinstance(node.value, bytes):
                return ('bytes', None)
        if isinstance(node, ast.Name):
            if node.id == '__file__' and script:
                return ('str', str(script))
            return env.get(node.id, ('module', symbols[node.id]) if node.id in symbols else ('unknown', None))
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            left, right = value(node.left, env), value(node.right, env)
            if left[0] == 'path' and right[0] == 'str' and right[1] is not None:
                return ('path', (left[1] / right[1]).resolve())
        if isinstance(node, ast.Attribute):
            base = value(node.value, env)
            if base[0] == 'path' and node.attr == 'parent':
                return ('path', base[1].parent)
        if isinstance(node, ast.Call):
            name = qualified(node.func)
            if name == 'pathlib.Path':
                arg = value(node.args[0], env) if node.args else ('str', str(cwd))
                if arg[0] in {'str', 'path'} and arg[1] is not None:
                    p = Path(arg[1]).expanduser()
                    return ('path', (p if p.is_absolute() else cwd / p).resolve())
            if name == 'pathlib.Path.cwd':
                return ('path', cwd)
            if name == 'pathlib.Path.home':
                return ('path', Path.home())
            if name in {'str', 'html.unescape', 're.sub', 're.subn'}:
                return ('str', None) if name != 're.subn' else ('unknown', None)
            if name == 'bytes':
                return ('bytes', None)
            if name in {'dict', 'list', 'set', 'tuple', 'bytearray'}:
                return ('data', None)
            if isinstance(node.func, ast.Attribute):
                obj = value(node.func.value, env)
                method = node.func.attr
                if obj[0] == 'path' and method in {'resolve', 'absolute', 'expanduser'}:
                    return obj
                if obj[0] == 'path' and method == 'read_text':
                    return ('str', None)
                if obj[0] == 'path' and method == 'read_bytes':
                    return ('bytes', None)
                if obj[0] in {'str', 'bytes'} and method in {'replace', 'strip', 'lstrip', 'rstrip', 'lower', 'upper'}:
                    return (obj[0], None)
                if obj[0] == 'bytes' and method == 'decode':
                    return ('str', None)
                if obj[0] in {'str', 'bytes'} and method in {'split', 'splitlines'}:
                    return ('data', None)
                if obj[0] == 'str' and method == 'encode':
                    return ('bytes', None)
                if obj[0] in {'file_text', 'file_bytes'} and method == 'read':
                    return ('str' if obj[0] == 'file_text' else 'bytes', None)
            if name == 'open' or (isinstance(node.func, ast.Attribute) and node.func.attr == 'open'):
                mode_node = next((k.value for k in node.keywords if k.arg == 'mode'),
                                 node.args[1] if name == 'open' and len(node.args) > 1 else
                                 node.args[0] if name != 'open' and node.args else ast.Constant('r'))
                mode = value(mode_node, env)
                target = value(node.args[0], env) if name == 'open' and node.args else value(node.func.value, env)
                if target[0] == 'str' and target[1] is not None:
                    p = Path(target[1]).expanduser()
                    target = ('path', (p if p.is_absolute() else cwd / p).resolve())
                if target[0] == 'path' and mode[0] == 'str' and mode[1]:
                    return ('file_bytes' if 'b' in mode[1] else 'file_text', target[1])
        return ('unknown', None)

    def call_risk(node, env):
        if not isinstance(node.func, (ast.Name, ast.Attribute)):
            return '动态选择的函数需要审查'
        name = qualified(node.func)
        leaf = name.rsplit('.', 1)[-1]
        if leaf in DANGEROUS or name.startswith(('os.exec', 'os.spawn', 'os.posix_spawn')):
            return f'Python 含删除、执行、反射或其他高风险调用：{name}'
        if isinstance(node.func, ast.Name) and node.func.id in env:
            return '间接函数调用需要审查'
        obj = value(node.func.value, env) if isinstance(node.func, ast.Attribute) else ('unknown', None)
        if name.startswith('sys.path.') or name.startswith('sys.modules.'):
            return '修改 Python 模块搜索路径或模块表需要审查'
        if name.startswith('os.environ.') and leaf not in {'get', 'copy', 'keys', 'items', 'values'}:
            return '修改环境变量需要审查'
        if obj[0] == 'module' and not name.startswith(tuple(symbols.values())):
            return '模块别名上的间接调用需要审查'
        if leaf == 'replace' and obj[0] not in {'str', 'bytes'}:
            return '不能证明 replace 的接收者是字符串或字节'
        if leaf in WRITE_METHODS or leaf == 'open':
            target = obj
            if leaf == 'open':
                mode = next((k.value for k in node.keywords if k.arg == 'mode'),
                            node.args[1] if name == 'open' and len(node.args) > 1 else
                            node.args[0] if name != 'open' and node.args else ast.Constant('r'))
                mode = value(mode, env)
                if mode[0] != 'str' or mode[1] is None:
                    return '文件打开模式不明确'
                if not any(c in mode[1] for c in 'wax+'):
                    target = value(node.args[0], env) if name == 'open' and node.args else obj
                    if target[0] == 'str' and target[1] is not None:
                        p = Path(target[1]).expanduser()
                        target = ('path', (p if p.is_absolute() else cwd / p).resolve())
                    if target[0] != 'path' or target[1] is None or protected(target[1]):
                        return 'Python 读取目标不明确或涉及配置'
                    return None
                target = value(node.args[0], env) if name == 'open' and node.args else obj
            if target[0] == 'str' and target[1] is not None:
                p = Path(target[1]).expanduser()
                target = ('path', (p if p.is_absolute() else cwd / p).resolve())
            if target[0] not in {'path', 'file_text', 'file_bytes'} or target[1] is None:
                return 'Python 写入目标无法静态确定，请使用受控入口或审查'
            if not inside(target[1]) or protected(target[1]):
                return 'Python 写入越界或涉及受保护配置'
            if leaf != 'mkdir' and target[1].exists() and not can_overwrite(target[1]):
                return 'Python 写入已有文件，需确认或本会话所有权'
        if leaf in {'read_text', 'read_bytes'} and obj[0] == 'path' and protected(obj[1]):
            return 'Python 读取受保护配置'
        if name in SAFE_CALLS:
            return None
        if name == 'open' or (obj[0] in SAFE_METHODS and leaf in SAFE_METHODS[obj[0]]):
            return None
        return f'未审定的 Python 调用：{name or leaf}'

    def statements(items, env):
        for stmt in items:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                local = dict(env)
                for arg in (*stmt.args.posonlyargs, *stmt.args.args, *stmt.args.kwonlyargs):
                    local[arg.arg] = ('unknown', None)
                issue = statements(stmt.body, local)
                if issue:
                    return issue
                continue
            # 分支/循环的赋值不用于证明后续变量安全，防止条件赋值导致类型混淆。
            if isinstance(stmt, (ast.If, ast.For, ast.While, ast.Try, ast.With, ast.AsyncWith, ast.Match)):
                for node in ast.walk(stmt):
                    if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                        env[node.id] = ('unknown', None)
                for node in ast.walk(stmt):
                    if isinstance(node, ast.Call):
                        issue = call_risk(node, env)
                        if issue:
                            return issue
                continue
            for node in ast.walk(stmt):
                if isinstance(node, ast.Call):
                    issue = call_risk(node, env)
                    if issue:
                        return issue
                if isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)):
                    return 'Python 修改对象属性，需要审查'
                if isinstance(node, ast.Subscript) and isinstance(node.ctx, (ast.Store, ast.Del)):
                    if qualified(node.value) in {'os.environ', 'sys.modules'}:
                        if qualified(node.value) == 'sys.modules' or not isinstance(node.slice, ast.Constant) or node.slice.value not in {'TMPDIR', 'TEMP', 'TMP'}:
                            return 'Python 修改运行时环境，需要审查'
            if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
                targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
                inferred = value(stmt.value, env)
                if isinstance(stmt.value, (ast.Attribute, ast.Name)) and inferred[0] == 'unknown':
                    inferred = ('callable', None)
                for target in targets:
                    if isinstance(target, ast.Name):
                        env[target.id] = inferred
        return None

    return statements(tree.body, {})
