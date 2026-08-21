# Bug Reproduction

## 包的性质

当前 test_model_fix 保存的是被测模型修复后的结果源码，不是初始含 Bug 源码。要复现原始缺陷，必须检出下面固定的 parent SHA；不要在当前修复结果源码上期待重新出现修复前失败。生成系统使用的可信验证补丁和完整验证日志仅在本地留存，不提交到结果分支。

## 问题现象

移动端值班员在登录转圈时切换网络并取消请求，页面明确没有收到令牌；几秒后安全后台却多出一条新在线会话，创建时间正好对应这次中断的登录，用户也无法主动退出这枚从未交付的凭证。密码校验较慢时更容易出现，正常完成的登录仍可使用。请修复登录取消后的状态交接：请求结束后不得再签发或保存调用方拿不到的会话，未取消的正确登录、错误密码和停用账号行为保持不变。

## 含 Bug 版本

- 仓库：VanceMichael/go-label-canalclear-g01-r15
- 仓库地址：https://github.com/VanceMichael/go-label-canalclear-g01-r15.git
- parent SHA：4257e31650a8af38e753c27d4b2f21960e81cda8

## 复现步骤

```bash
git clone -- https://github.com/VanceMichael/go-label-canalclear-g01-r15.git bug-repro
cd bug-repro
git checkout --detach 4257e31650a8af38e753c27d4b2f21960e81cda8
go test ./internal/auth -run ^TestCancelledLoginNeverPersistsSession$ -count=1
```

## 双架构完整错误信息

### linux/amd64

- 容器内复现预期退出码：1
- 容器内复现实际退出码：1

stdout：

```text
$ go test ./internal/auth -run ^TestCancelledLoginNeverPersistsSession$ -count=1
--- FAIL: TestCancelledLoginNeverPersistsSession (0.00s)
    login_test.go:95: created sessions after the cancelled attempt finished = 1, want 0
FAIL
FAIL	github.com/VanceMichael/go-base-canalclear-g01/internal/auth	0.034s
FAIL

```

stderr：

```text
(empty)
```

### linux/arm64

- 容器内复现预期退出码：1
- 容器内复现实际退出码：1

stdout：

```text
$ go test ./internal/auth -run ^TestCancelledLoginNeverPersistsSession$ -count=1
--- FAIL: TestCancelledLoginNeverPersistsSession (0.00s)
    login_test.go:95: created sessions after the cancelled attempt finished = 1, want 0
FAIL
FAIL	github.com/VanceMichael/go-base-canalclear-g01/internal/auth	0.002s
FAIL

```

stderr：

```text
(empty)
```

## 通过条件

当登录请求在慢密码校验结束前被取消时，调用必须及时返回 context.Canceled 且不交付令牌；校验任务随后收尾也不能创建任何会话。未取消的有效凭据仍可获得可鉴权会话，错误密码和停用账号继续被拒绝。必须让 go test -race ./internal/auth -run ^TestCancelledLoginNeverPersistsSession$ -count=1 和完整 Go 回归通过，不得删除或跳过目标测试、放宽会话计数及取消结果断言来规避缺陷。
