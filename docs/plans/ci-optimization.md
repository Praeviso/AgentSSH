# CI 按影响范围执行与提速

## 目标与验收

- PR 与 main push 使用同一套选择规则；纯 README/docs/skills 改动不启动 Go。
- 测试文件只运行所属包；生产 Go 改动覆盖该包及其传递调用方，包含外部测试依赖。
- 依赖、CI 配置、未知文件、删除/重命名、无法解析 diff/依赖图时回退全量；分析失败不能成为绿色跳过。
- quality、内部包 race、CLI race 独立反馈；统一 ci-result 检查实际执行与预期一致，失败/取消不能放行。
- 每日、手动及发布前执行完整的非缓存 race 测试；发布等待验证与构建都通过。
- 模块缓存与不同用途的构建缓存分开，构建缓存随源码更新；同 PR 新提交取消旧 CI。
- 用低成本 age fixture 减少 CLI 设置 verifier 的重复 scrypt，保留真实解密与错误密码检查，以及生产参数写入路径验证；不修改生产密码学参数。
- 完成一次整体校验，提交分支并创建 PR，核对远端 CI。

## 方案

沿用 docs/plans 的仓库约定。工作流入口先做无需 Go 的分类，再在需要时通过 go list 的 Imports/TestImports/XTestImports 计算影响范围。脚本只使用 Python 标准库，提供本地可复现接口和真实 Git/Go fixture 验收。

实现顺序：选择器与行为测试 → 工作流/缓存/汇总 → 测试 fixture → 文档 → 集中验证与修复 → 提交和 PR。发布复用全量工作流，验证与交叉编译并行。

## 进度

- [x] 核对 main、工作区、既有 CI 与慢测试：最新成功 race 414s，其中 CLI 395s。
- [x] 选择器与回退行为，真实 Git/Go fixture 和汇总失败测试。
- [x] 日常/全量/发布工作流与缓存。
- [x] CLI fixture 和通过 operator init 的生产参数覆盖；生产代码零改动。
- [x] 最终本地验证、性能记录、文档。
- [x] 提交、推送并创建 [PR #9](https://github.com/Praeviso/AgentSSH/pull/9)；远端检查以 PR Checks 为准。

## 验证

计划：Python unittest（真实临时 Git 仓库和 Go 依赖图）；actionlint；脚本语法；gofmt；go vet ./...；两个 CLI 构建；go test -race -count=1 -json -timeout=20m ./...；CI 固定版 golangci-lint；git diff --check。使用单项 JSON 计时记录新耗时，并验证文档、测试文件、传递依赖、跨包测试依赖、删除/重命名、未知文件、分析失败以及汇总失败/取消行为。

结果（2026-10-20）：

- 21 项 Python 行为测试通过，包含真实 Git 历史、race 专用依赖、包内/外测试依赖和失败测试 JSON/退出码。
- actionlint v1.7.12、shell 语法、gofmt、go vet、两个 CLI 构建、golangci-lint v2.12.2（0 issues）、git diff --check 通过。
- 最终 go test -race -count=1 -json -timeout=20m ./... 全部通过，墙钟 64.837s，CLI 包 64.220s。
- 审计 demo --no-tui 通过，另行断言恰有 6 个 pending 请求。
- 首轮验证发现 fixture 写入缺失父目录的问题，修复后原失败用例和完整验证均通过。
- 新增远端 actionlint 检查发现原发布脚本的 SC2035 glob 提示；改为 cat -- ./*.tar.gz.sha256，并补齐本地 shellcheck 验证。
- 本地耗时和历史 hosted runner 环境不同，不据此声称精确提升比例；PR CI 用于记录 hosted runner 数据。

交付：[PR #9](https://github.com/Praeviso/AgentSSH/pull/9)，分支 ci/affected-tests-and-speedups。远端运行记录见该 PR 的 Checks；不合并或发布版本。
