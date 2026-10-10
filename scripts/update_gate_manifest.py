"""更新独立 Hook 内容哈希清单；不打包或安装插件。"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path

BASE = Path(__file__).resolve().parent
FILES = ('security_gate.py', 'python_check.py', 'scoped_text_job.py')

def build():
    manifest = {'version': '3.0.0', 'files': {
        name: hashlib.sha256((BASE / name).read_bytes()).hexdigest() for name in FILES}}
    path = BASE / 'gate_manifest.json'
    path.write_text(json.dumps(manifest, indent=2) + '\n')
    return path

if __name__ == '__main__':
    print(build())
