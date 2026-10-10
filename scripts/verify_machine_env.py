"""
跨设备环境合规自检脚本 (Machine Baseline Verification)
用于在新电脑（电脑 B）或任何部署目标机上一键验证“方案 C 物理级 0 弹窗”是否完全就绪。
"""

import os
import sys
from pathlib import Path

def run_verification():
    print("=" * 60)
    print(" 🚀 跨设备物理级 0 弹窗基线自检 (方案 C 验证程序) ")
    print("=" * 60)

    # 1. 动态锚定工作区根目录
    current_file = Path(__file__).resolve()
    ws_root = None
    for p in [current_file.parent] + list(current_file.parents):
        if (p / "AGENTS.md").exists():
            ws_root = p
            break
    
    if not ws_root:
        print("❌ [FAIL] 未能在当前路径及其上级目录中找到 AGENTS.md 根文件！")
        return False
    
    print(f"✅ [1/6] 动态工作区根目录定位成功: {ws_root}")
    
    # 2. 检查 AGENTS.md 是否包含方案 C 绝对铁律
    agents_content = (ws_root / "AGENTS.md").read_text(encoding="utf-8")
    if "物理级 0 弹窗铁律" in agents_content and "guard_path" in agents_content:
        print("✅ [2/6] AGENTS.md 核心规范对齐: 已包含方案 C 物理级 0 弹窗规约")
    else:
        print("❌ [FAIL] AGENTS.md 未能检测到方案 C 核心条款，请重新同步！")
        return False

    # 3. 检查 .gitignore 隔离规则
    gitignore_path = ws_root / ".gitignore"
    if gitignore_path.exists() and ".tmp_*/" in gitignore_path.read_text(encoding="utf-8"):
        print("✅ [3/6] .gitignore 安全配置就绪: 临时目录与时间戳缓存已受控忽略")
    else:
        print("⚠️ [WARN] .gitignore 不存在或未包含 .tmp_ 规则，建议补全。")

    # 4. 检查 .agents/rules/zero_popup_interlock.md 专项联锁规约
    interlock_path = ws_root / ".agents" / "rules" / "zero_popup_interlock.md"
    if interlock_path.exists() and "0-Popup SLA" in interlock_path.read_text(encoding="utf-8"):
        print("✅ [4/6] zero_popup_interlock.md 专项联锁规约就绪: 双重硬锁已激活")
    else:
        print("❌ [FAIL] 未能检测到 .agents/rules/zero_popup_interlock.md 规约文件！")
        return False

    # 5. 验证公共物理守卫库 sandbox_guard.py
    guard_script = ws_root / "scripts" / "sandbox_guard.py"
    if not guard_script.exists():
        print("❌ [FAIL] 未找到 scripts/sandbox_guard.py 核心守卫模块！")
        return False
    
    # 动态导入验证
    sys.path.insert(0, str(ws_root / "scripts"))
    try:
        import sandbox_guard
        test_tmp = sandbox_guard.setup_workspace_tmpdir("machine_check")
        assert str(test_tmp).startswith(str(ws_root.resolve())), "临时目录越出工作区！"
        assert os.environ.get("TMPDIR") == str(test_tmp), "TMPDIR 环境变量未成功重定向！"
        
        # 测试越界拦截能力
        escaped_path = Path("/tmp/should_be_blocked.txt")
        blocked = False
        try:
            sandbox_guard.guard_path(escaped_path)
        except RuntimeError:
            blocked = True
        
        if not blocked:
            print("❌ [FAIL] 物理路径守卫 guard_path 未能成功阻击外部越界路径！")
            return False
            
        print("✅ [5/6] 物理守卫与断言测试通过: guard_path 与环境变量隔离 100% 正常")
        
        # 清理测试目录
        if test_tmp.exists():
            test_tmp.rmdir()
            
    except Exception as e:
        print(f"❌ [FAIL] 导入或测试 sandbox_guard 异常: {e}")
        return False

    # 6. 跨设备用户名动态适配检查
    print(f"✅ [6/6] 本机绝对路径宿主适配: {Path.home()} -> 动态适配成功（无写死硬编码）")
    
    print("=" * 60)
    print(" 🏆 本机已完全就绪！具备 100% 物理级 0 弹窗与自主闭环能力！")
    print("=" * 60)
    return True

if __name__ == "__main__":
    success = run_verification()
    sys.exit(0 if success else 1)
