from __future__ import annotations
import copy
import importlib.util
import json
import sys
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


gate = module('gate', ROOT / 'scripts/security_gate.py')
manager = module('manager', ROOT / 'scripts/manage_gate.py')
runner = module('runner', ROOT / 'scripts/scoped_text_job.py')
guard = module('guard', ROOT / 'scripts/sandbox_guard.py')
build = module('build', ROOT / 'scripts/update_gate_manifest.py')
CID = '00000000-0000-4000-8000-000000000001'


class GateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.ws = self.root / 'workspace'
        self.ws.mkdir()
        self.payload = {'conversationId': CID, 'workspacePaths': [str(self.ws)],
                        'toolCall': {'name': 'run_command', 'args': {'Cwd': str(self.ws), 'CommandLine': 'pwd'}}}

    def evaluate(self, args=None, name='run_command', **fields):
        payload = copy.deepcopy(self.payload)
        payload.update(fields)
        if args:
            payload['toolCall'] = {'name': name, 'args': args}
        g = gate.Gate(payload, state_dir=self.root / 'state')
        result = type('Result', (), {'returncode': 0, 'stdout': '{"schema_version":1,"decision":"allow"}'})()
        with patch.object(gate.subprocess, 'run', return_value=result):
            return g.evaluate()

    def command(self, cmd):
        return self.evaluate({'Cwd': str(self.ws), 'CommandLine': cmd})['decision']

    def py(self, source, suffix=''):
        p = self.ws / 'sample.py'
        p.write_text(source)
        return self.command(f'python3 {p} {suffix}')

    def test_string_replace(self):
        self.assertEqual(self.py("text='abc'; print(text.replace('a','b'))"), 'allow')

    def test_re_sub_string(self):
        self.assertEqual(self.py("import re\ntext=re.sub('a','b','abc')\nprint(text.replace('b','c'))"), 'allow')

    def test_path_replace(self):
        self.assertEqual(self.py("from pathlib import Path\np=Path('a'); p.replace('b')"), 'force_ask')

    def test_alias_delete(self):
        self.assertEqual(self.py("from os import unlink as erase\nerase('a')"), 'force_ask')

    def test_indirect_delete(self):
        self.assertEqual(self.py("import os\nf=os.unlink\nf('a')"), 'force_ask')

    def test_interpreter_flags_and_arguments(self):
        p = self.ws / 'sample.py'
        p.write_text("import shutil\nshutil.rmtree('a')")
        for cmd in [f'python3 -B {p}', f'python3 -I -u {p} --dry-run', f'python3 {p} --flag', f'echo ok && python3 {p} --flag']:
            with self.subTest(cmd=cmd):
                self.assertEqual(self.command(cmd), 'force_ask')

    def test_unknown_write(self):
        self.assertEqual(self.py("from pathlib import Path\nimport sys\np=Path(sys.argv[1]); p.write_text('x')", 'out.md'), 'force_ask')

    def test_static_inside_write(self):
        self.assertEqual(self.py("from pathlib import Path\np=Path('out.md'); p.write_text('x')"), 'allow')

    def test_python_existing_file_needs_approval(self):
        (self.ws / 'out.md').write_text('user data')
        self.assertEqual(self.py("from pathlib import Path\np=Path('out.md'); p.write_text('x')"), 'force_ask')
        self.assertEqual((self.ws / 'out.md').read_text(), 'user data')

    def test_executable_name_spoofing(self):
        executable = self.ws / 'ls'
        executable.write_text('malicious placeholder, never executed')
        self.assertEqual(self.command(str(executable)), 'force_ask')

    def test_environment_and_module_path_mutation(self):
        for source in ["import os\nos.environ.update({'PATH':'/tmp'})", "import os\ne=os.environ\ne.update({'PATH':'/tmp'})", "import sys\nsys.path.insert(0,'/tmp')"]:
            self.assertEqual(self.py(source), 'force_ask')

    def test_unknown_methods_and_binding_bypasses(self):
        for source in [
            "import os\nos.open('a', 1)",
            "from pathlib import Path\ntext='a'\n(text:=Path('a'))\ntext.replace('b')",
            "from pathlib import Path\ntext='a'\ntext,=[Path('a')]\ntext.replace('b')",
            "import os\nprint(os.environ)",
            "@print('x')\ndef f():\n pass",
        ]:
            self.assertEqual(self.py(source), 'force_ask')

    def test_relative_executable_spoofing_and_tool_side_effects(self):
        for cmd in ['./ls', 'file -C magic', 'rg --hostname-bin=malicious x', 'echo x > output*']:
            self.assertEqual(self.command(cmd), 'force_ask')

    def test_static_outside_write(self):
        self.assertEqual(self.py("from pathlib import Path\np=Path('/tmp/out.md'); p.write_text('x')"), 'force_ask')

    def test_protected_write(self):
        self.assertEqual(self.py("from pathlib import Path\np=Path('.agents/config.json'); p.write_text('x')"), 'force_ask')

    def test_reflection(self):
        for code in ["getattr(__import__('os'),'unlink')('a')", "__builtins__['eval']('1')", "str='x'; str('a')", "def f(str):\n return str('a').replace('a','b')"]:
            self.assertEqual(self.py(code), 'force_ask')

    def test_branch_type_confusion(self):
        self.assertEqual(self.py("from pathlib import Path\ntext='a'\nif True:\n text=Path('a')\n text.replace('b')"), 'force_ask')

    def test_annotation_is_not_proof(self):
        self.assertEqual(self.py("def clean(text: str):\n return text.replace('a','b')"), 'force_ask')

    def test_unknown_dependency(self):
        self.assertEqual(self.py("import subprocess\nsubprocess.run(['pwd'])"), 'force_ask')

    def test_shadowed_stdlib(self):
        (self.ws / 're.py').write_text('')
        self.assertEqual(self.py("import re\ntext=re.sub('a','b','c')"), 'force_ask')

    def test_python_startup_injection_needs_isolation(self):
        (self.ws / 'sitecustomize.py').write_text('never executed')
        self.assertEqual(self.command('python3 -c "print(1)"'), 'force_ask')
        self.assertEqual(self.command('python3 -I -c "print(1)"'), 'allow')

    def test_dev_null(self):
        self.assertEqual(self.command('python3 -c "import sys; print(sys.executable)" && ls -d /Applications/*[Cc]alibre* 2>/dev/null || true'), 'allow')

    def test_redirect_existing(self):
        (self.ws / 'a').write_text('original')
        self.assertEqual(self.command('echo changed > a'), 'force_ask')
        self.assertEqual((self.ws / 'a').read_text(), 'original')

    def test_destructive_shell(self):
        for cmd in ['rm -rf a', 'echo ok && rm a', 'sh -c "rm a"', 'git reset --hard', 'git -c alias.x="!rm a" x', 'rg --pre "rm a" text']:
            self.assertEqual(self.command(cmd), 'force_ask')

    def test_readonly_git(self):
        for cmd in ['git status --short', 'git diff --check', 'git log -1', 'git ls-files']:
            self.assertEqual(self.command(cmd), 'allow')

    def test_dcg_failure(self):
        g = gate.Gate(self.payload, state_dir=self.root / 'state')
        with patch.object(gate.subprocess, 'run', side_effect=FileNotFoundError):
            self.assertEqual(g.evaluate()['decision'], 'force_ask')

    def test_dcg_bad_protocol(self):
        g = gate.Gate(self.payload, state_dir=self.root / 'state')
        with patch.object(gate.subprocess, 'run', return_value=type('R', (), {'returncode': 0, 'stdout': '{}'})()):
            self.assertEqual(g.evaluate()['decision'], 'force_ask')

    def test_missing_roots(self):
        with self.assertRaises(ValueError):
            gate.Gate({**self.payload, 'workspacePaths': []})

    def test_cross_workspace(self):
        outside = self.root / 'other/new.txt'
        self.assertEqual(self.evaluate({'TargetFile': str(outside), 'CodeContent': 'x'}, name='write_to_file')['decision'], 'force_ask')

    def test_sibling_prefix(self):
        outside = Path(str(self.ws) + '-outside') / 'a'
        with self.assertRaises(RuntimeError):
            guard.guard_path(outside, self.ws)

    def test_root_and_task_id(self):
        with self.assertRaises(RuntimeError):
            guard.guard_path(self.ws, self.ws)
        with self.assertRaises(ValueError):
            guard.setup_workspace_tmpdir('../../outside')

    def test_symlink(self):
        (self.ws / 'link').symlink_to(self.root)
        self.assertEqual(self.evaluate({'TargetFile': str(self.ws / 'link/a'), 'CodeContent': 'x'}, name='write_to_file')['decision'], 'force_ask')

    def test_artifacts_all_hosts(self):
        for app in ['antigravity', 'antigravity-ide', 'antigravity-cli']:
            artifact = Path.home() / '.gemini' / app / 'brain' / CID
            result = self.evaluate({'TargetFile': str(artifact / 'task.md'), 'CodeContent': 'x'}, name='write_to_file', artifactDirectoryPath=str(artifact))
            self.assertEqual(result['decision'], 'allow')
        wrong = Path.home() / '.gemini/antigravity/brain/another'
        with self.assertRaises(ValueError):
            self.evaluate(artifactDirectoryPath=str(wrong))

    def test_artifact_transcript_is_protected(self):
        artifact = Path.home() / '.gemini/antigravity/brain' / CID
        result = self.evaluate({'TargetFile': str(artifact / '.system_generated/logs/transcript.jsonl'), 'CodeContent': 'forged'},
                               name='write_to_file', artifactDirectoryPath=str(artifact))
        self.assertEqual(result['decision'], 'force_ask')

    def test_only_pre_event_does_not_own_file(self):
        path = self.ws / 'new.py'
        args = {'TargetFile': str(path), 'CodeContent': 'original'}
        self.assertEqual(self.evaluate(args, 'write_to_file')['decision'], 'allow')
        path.write_text('original')
        self.assertEqual(self.evaluate({**args, 'CodeContent': 'new'}, 'write_to_file')['decision'], 'force_ask')

    def test_ownership_success_edit_and_cross_conversation(self):
        path = self.ws / 'new.py'
        args = {'TargetFile': str(path), 'CodeContent': 'original'}
        self.evaluate(args, 'write_to_file')
        path.write_text('original')
        payload = {**self.payload, 'toolCall': {'name': 'write_to_file', 'args': args}}
        gate.Gate(payload, state_dir=self.root / 'state').post()
        self.assertEqual(self.evaluate({**args, 'CodeContent': 'new'}, 'write_to_file')['decision'], 'allow')
        self.assertEqual(self.evaluate({**args, 'CodeContent': 'new'}, 'write_to_file', conversationId='00000000-0000-4000-8000-000000000002')['decision'], 'force_ask')
        path.write_text('user edit')
        self.assertEqual(self.evaluate({**args, 'CodeContent': 'new'}, 'write_to_file')['decision'], 'force_ask')

    def test_failed_post_does_not_own(self):
        path = self.ws / 'new.py'
        args = {'TargetFile': str(path), 'CodeContent': 'original'}
        self.evaluate(args, 'write_to_file')
        path.write_text('original')
        payload = {**self.payload, 'error': 'failed', 'toolCall': {'name': 'write_to_file', 'args': args}}
        gate.Gate(payload, state_dir=self.root / 'state').post()
        self.assertEqual(self.evaluate({**args, 'CodeContent': 'new'}, 'write_to_file')['decision'], 'force_ask')

    def test_partial_edit_cannot_claim_user_modified_owned_file(self):
        path = self.ws / 'new.py'
        args = {'TargetFile': str(path), 'CodeContent': 'original'}
        self.evaluate(args, 'write_to_file')
        path.write_text('original')
        payload = {**self.payload, 'toolCall': {'name': 'write_to_file', 'args': args}}
        gate.Gate(payload, state_dir=self.root / 'state').post()
        path.write_text('user change')
        edit = {'TargetFile': str(path), 'TargetContent': 'change', 'ReplacementContent': 'edit'}
        self.evaluate(edit, 'replace_file_content')
        path.write_text('user edit')
        gate.Gate({**self.payload, 'toolCall': {'name': 'replace_file_content', 'args': edit}}, state_dir=self.root / 'state').post()
        self.assertEqual(self.evaluate({**args, 'CodeContent': 'new'}, 'write_to_file')['decision'], 'force_ask')

    def test_tmp_name_does_not_grant_ownership(self):
        p = self.ws / '.tmp_pipeline/user.py'
        p.parent.mkdir()
        p.write_text('user')
        self.assertEqual(self.evaluate({'TargetFile': str(p), 'CodeContent': 'new'}, 'write_to_file')['decision'], 'force_ask')

    def test_post_tool_metadata_differences(self):
        path = self.ws / 'meta.py'
        args = {'TargetFile': str(path), 'CodeContent': 'original'}
        self.evaluate(args, 'write_to_file')
        path.write_text('original')
        call = {'name': 'write_to_file', 'args': args, 'toolSummary': 'host summary'}
        gate.Gate({**self.payload, 'toolCall': call}, state_dir=self.root / 'state').post()
        self.assertEqual(self.evaluate({**args, 'CodeContent': 'changed'}, 'write_to_file')['decision'], 'allow')

    def test_fixed_text_entry_contract(self):
        (self.ws / 'input.md').write_text('a')
        job = self.ws / 'job.json'
        job.write_text(json.dumps({'input': 'input.md', 'output': 'out.md', 'replacements': [['a', 'b']]}))
        cmd = f'python3 -I {gate.BASE / "scoped_text_job.py"} --workspace {self.ws} --job {job}'
        self.assertEqual(self.command(cmd), 'allow')
        self.assertEqual(self.command(cmd.replace(' -I ', ' ')), 'force_ask')
        (self.ws / 'out.md').write_text('user output')
        self.assertEqual(self.command(cmd), 'force_ask')


class InstallTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.home, self.ws = self.root / 'home', self.root / 'workspace'
        self.home.mkdir()
        self.ws.mkdir()
        self.hooks = self.home / '.gemini/config/hooks.json'
        self.hooks.parent.mkdir(parents=True)
        self.original = {'unrelated': {'enabled': True}, 'intelligent-safety-gate': {'PreToolUse': [{'hooks': [{'command': f'python3 -I {self.home}/.gemini/config/scripts/security_gate.py'}]}]}}
        self.hooks.write_text(json.dumps(self.original))
        (self.ws / 'AGENTS.md').write_text('original user rules')
        (self.ws / 'keep.txt').write_text('untouched')

    def install(self):
        return manager.install(self.home, self.ws, Path(sys.executable))

    def test_install_repeat_restore_preserve_unrelated(self):
        result = self.install()
        self.assertTrue(json.loads(self.hooks.read_text())['intelligent-safety-gate']['enabled'])
        self.assertEqual(self.install()['status'], 'already_installed')
        current = json.loads(self.hooks.read_text())
        current['later_user_hook'] = {'enabled': True}
        self.hooks.write_text(json.dumps(current))
        manager.restore(Path(result['backup_manifest']))
        self.assertEqual((self.ws / 'AGENTS.md').read_text(), 'original user rules')
        self.assertEqual((self.ws / 'keep.txt').read_text(), 'untouched')
        self.assertIn('later_user_hook', json.loads(self.hooks.read_text()))

    def test_restore_refuses_user_edits(self):
        result = self.install()
        (self.ws / 'AGENTS.md').write_text('later user rules')
        with self.assertRaises(ValueError):
            manager.restore(Path(result['backup_manifest']))
        self.assertEqual((self.ws / 'AGENTS.md').read_text(), 'later user rules')

    def test_symlink_target_refused(self):
        (self.ws / 'AGENTS.md').unlink()
        (self.ws / 'AGENTS.md').symlink_to(self.ws / 'keep.txt')
        with self.assertRaises(ValueError):
            self.install()

    def test_unrecognized_legacy_hook_refused(self):
        self.original['intelligent-safety-gate']['PreToolUse'][0]['hooks'][0]['command'] = 'another-gate'
        self.hooks.write_text(json.dumps(self.original))
        with self.assertRaises(ValueError):
            self.install()

    def test_transaction_failure_rolls_back(self):
        real_write = manager.write
        def failing(path, data, mode=0o600):
            if path == self.ws / 'AGENTS.md':
                raise OSError('injected failure')
            return real_write(path, data, mode)
        with patch.object(manager, 'write', side_effect=failing):
            with self.assertRaises(OSError):
                self.install()
        self.assertEqual(json.loads(self.hooks.read_text()), self.original)
        self.assertEqual((self.ws / 'AGENTS.md').read_text(), 'original user rules')

    def test_fresh_home_restore_removes_new_hook_file(self):
        self.hooks.unlink()
        result = self.install()
        manager.restore(Path(result['backup_manifest']))
        self.assertFalse(self.hooks.exists())


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.ws = Path(self.tmp.name).resolve()
        (self.ws / 'input.md').write_text('a\u200bb')
        self.job = self.ws / 'job.json'
        self.job.write_text(json.dumps({'input': 'input.md', 'output': 'out.md', 'replacements': [['\u200b', '']]}))

    def test_safe_new_output_and_backup(self):
        runner.run(self.job, self.ws)
        self.assertEqual((self.ws / 'out.md').read_text(), 'ab')
        with self.assertRaises(ValueError):
            runner.run(self.job, self.ws)
        job = json.loads(self.job.read_text())
        job['overwrite'] = True
        self.job.write_text(json.dumps(job))
        result = runner.run(self.job, self.ws)
        self.assertEqual(Path(result['backup']).read_text(), 'ab')

    def test_escape_and_protected(self):
        for output in ['../escape.md', '.agents/secret.md', 'AGENTS.md', '.env']:
            self.job.write_text(json.dumps({'input': 'input.md', 'output': output}))
            with self.assertRaises(ValueError):
                runner.run(self.job, self.ws)


    def test_output_symlink(self):
        (self.ws / 'out.md').symlink_to(self.ws / 'input.md')
        with self.assertRaises(ValueError):
            runner.run(self.job, self.ws)


class HookProtocolTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.home, self.ws = self.root / 'home', self.root / 'workspace'
        self.home.mkdir()
        self.ws.mkdir()
        manager.install(self.home, self.ws, Path(sys.executable))
        self.entry = self.home / '.gemini/config/scripts/security_gate.py'
        self.payload = {'conversationId': CID, 'workspacePaths': [str(self.ws)],
                        'toolCall': {'name': 'run_command', 'args': {'Cwd': str(self.ws), 'CommandLine': 'pwd'}}}

    def invoke(self, payload, phase='pre'):
        raw = payload if isinstance(payload, str) else json.dumps(payload)
        result = subprocess.run([sys.executable, '-I', str(self.entry), phase], input=raw,
                                text=True, capture_output=True, timeout=8)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_real_stdin_stdout_pre_post_and_audit(self):
        self.assertEqual(self.invoke(self.payload)['decision'], 'allow')
        path = self.ws / 'owned.txt'
        call = {'name': 'write_to_file', 'args': {'TargetFile': str(path), 'CodeContent': 'created'}}
        payload = {**self.payload, 'toolCall': call}
        self.assertEqual(self.invoke(payload)['decision'], 'allow')
        path.write_text('created')
        self.assertEqual(self.invoke(payload, 'post'), {})
        call['args']['CodeContent'] = 'updated'
        self.assertEqual(self.invoke(payload)['decision'], 'allow')
        records = [json.loads(s) for s in (self.home / '.gemini/config/safety_gate_state/audit.jsonl').read_text().splitlines()]
        self.assertTrue(all(r['version'] == '3.0.0' for r in records))
        self.assertIn('post', [r['event'] for r in records])

    def test_malformed_input_is_fail_closed(self):
        self.assertEqual(self.invoke('{broken')['decision'], 'force_ask')

    def test_symlink_audit_is_fail_closed(self):
        state = self.home / '.gemini/config/safety_gate_state'
        state.mkdir()
        target = self.root / 'user-log'
        target.write_text('preserve')
        (state / 'audit.jsonl').symlink_to(target)
        self.assertEqual(self.invoke(self.payload)['decision'], 'force_ask')
        self.assertEqual(target.read_text(), 'preserve')

class SkillGuardTests(unittest.TestCase):
    def test_tmp_validation_precedes_creation_and_root_is_protected(self):
        with zipfile.ZipFile(ROOT / 'ebook-to-markdown-pipeline.skill') as z:
            namespace = {}
            exec(compile(z.read('ebook-to-markdown-pipeline/scripts/workspace_sandbox.py'), '<bundled-guard>', 'exec'), namespace)
        with tempfile.TemporaryDirectory(prefix='.tmp_skill_guard_', dir=ROOT) as tmp:
            root = Path(tmp).resolve()
            for job in ['../../escaped', '/tmp/outside', '', 'a/b']:
                with self.assertRaises(ValueError):
                    namespace['tmp_dir'](root, job)
            self.assertFalse((root / '.tmp_pipeline').exists())
            with self.assertRaises(ValueError):
                namespace['safe_rmtree'](root, root)
            self.assertTrue(root.is_dir())
            self.assertTrue(namespace['tmp_dir'](root, 'job-001').is_dir())


if __name__ == '__main__':
    build.build()
    unittest.main()
