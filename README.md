# Antigravity 双机配置与独立安全 Hook

本仓库同步工程规则、技能与独立 Hook，目标是减少已定义常规操作的反复确认，并保留删除、重要文件覆盖、配置修改、越界和检查失败的防护。没有插件，也没有自动点击授权程序；不承诺任意任务零弹窗。

## 更新与安装

先在本机保存本地修改。已有仓库有未提交改动时，不要强制覆盖、重置或清理。下面第一行切换到已经克隆的仓库根目录；若实际路径不同，先替换该行。

```sh
cd "$HOME/Documents/ChatGPT/同步IDE工具的配置/Antigravity--peizhi"
git status --short
git pull --ff-only
python3 -B tests/test_gate.py
python3 -B scripts/verify_machine_env.py --source-only
python3 -B scripts/manage_gate.py plan --workspace "$HOME/Documents/【Antigravity-IDE-projects】"
python3 -B scripts/manage_gate.py install --workspace "$HOME/Documents/【Antigravity-IDE-projects】"
python3 -B scripts/verify_machine_env.py --workspace "$HOME/Documents/【Antigravity-IDE-projects】" --output machine-check.json
```

需要 Python 3.10+，并在 `~/.local/bin/dcg` 安装兼容的 DCG（本机验证版本 0.7.8，`test --robot --stdin --heredoc-scan` 协议版本 1）。缺失、异常或超时继续询问，安装不会下载依赖。两台电脑用户名和项目路径可以不同；比较 `policy_version`、三个 `policy_hashes` 和每个案例的决策结果。

安装先写运行脚本，最后更新 `~/.gemini/config/hooks.json` 中已识别的 `intelligent-safety-gate`。保留其他 Hook、全局设置、凭据和权限缓存；备份清单包含原文件哈希与安装后哈希。只接受指向既定安全脚本的旧 Hook，未知同名实现拒绝覆盖。

## 安全范围与行为

- 只读目录检查、可确定类型的字符串替换、明确的 `2>/dev/null` 可以自动批准。
- Python 的每个命令段、解释器选项和带参数脚本都接受检查；未知调用、导入、反射和运行时修改继续询问。静态检查不是任意 Python 的安全证明。
- 新建、局部编辑可自动批准；整文件更新仅适用于成功创建且哈希未改变的本会话文件，或当前会话 Artifact。用户修改过的文件和其他会话的文件继续确认。
- 实际工作区来自宿主 `workspacePaths`；Artifact 适配 Antigravity、Antigravity IDE 和 CLI 的当前会话目录。
- 原生权限和操作系统沙箱继续生效。`allow` 不证明其他权限层也批准。符号链接与执行期间路径竞争仍需原生沙箱兜底，不能关闭它来验收。
- DCG 只评估候选命令，不执行它。机器自检同样不会执行删除或越界候选。

固定文本处理入口接受 JSON 数据，输出为新文件时采用排他创建；已有文件需要明确 `overwrite: true`，Hook 仍询问，执行时先保存备份。示例在当前工作区创建 `job.json`：

```json
{"input":"input.md","output":"output.md","replacements":[["\u200b",""]],"overwrite":false}
```

在真实工作区内执行（工作区路径须替换为当前项目）：

```sh
cd "$HOME/Documents/【Antigravity-IDE-projects】"
python3 -I "$HOME/.gemini/config/scripts/scoped_text_job.py" --workspace "$PWD" --job "$PWD/job.json"
```

该入口只做明确的 UTF-8 字符串清洗，不替代电子书提取或第三方转换器。复杂解析仍按实际脚本审查。运行状态和审计只保存在本机 `~/.gemini/config/safety_gate_state/`，不会同步到 GitHub。

## 回退

安装输出 `backup_manifest`。在仓库根目录执行以下命令，把路径换成该次安装输出的完整路径：

```sh
python3 -B scripts/manage_gate.py restore --manifest "$HOME/.gemini/config/backups/intelligent-safety-gate/该次备份目录/manifest.json"
```

回退前校验所有安装后哈希；用户后续改过的文件拒绝覆盖。其他 Hook 的后续修改保留，回退先恢复旧 Hook 再恢复代码。安装失败自动回退已写内容；新建空目录和运行审计保留用于调查。

## 验收分层

1. 仓库提交与部署文件哈希一致。
2. 全局配置指向本机正确的 Python 与安全脚本，独立决策测试通过。
3. 真实应用任务日志显示版本 3.0.0 的 Hook 调用，已定义常规操作连续执行；危险候选在批准前无副作用。
4. 完整重启应用两次后重复相同案例。
5. 第二台电脑安装同一提交，策略哈希和相同案例结果一致。

`verify_machine_env.py` 只证明前两层和独立调用的决策，不宣称后三层通过。实际宿主覆盖版本与重启结果应记录在交付报告中。

官方接口依据：[Hook 配置与输入输出协议](https://antigravity.google/docs/hooks)。
