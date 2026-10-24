# 驱动与内核执行端：边界说明

版本：`1.1.0-night-20261025`

## 1. 本包包含什么

本包新增**源码级** HIPS 内核执行端，位于 `driver/`：

- `HipsDriver.c` / `HipsDriver.h`：设备、IOCTL、进程终止、文件删除；
- `HipsDriver.inf`：legacy 内核服务安装模板；
- `HipsClient.c`：用户态调用示例；
- `HipsTestTarget.c`：VM 内良性占用/映射测试目标；
- `build_driver_msvc.ps1`、`sign_test_driver.ps1`；
- `README.md`：构建、测试签名、VM 安装、限制。

GUI **不会**加载或安装该驱动；“安全设置”只显示服务状态。驱动是独立的、显式选择的测试组件。

## 2. 安全设计

- 设备 ACL：`D:P(A;;GA;;;SY)`，只允许 SYSTEM 打开；
- 破坏性 IOCTL 额外检查 `FILE_WRITE_ACCESS`；
- 不提供任意内核读写、任意进程内存读写、句柄枚举、SSDT/Hook；
- 进程终止拒绝 PID 0/4；
- 文件删除只接受 NT 绝对路径（`\??\...` 或 `\Device\...`）；
- 所有输入做长度/版本/标志校验；
- 驱动卸载删除符号链接与设备对象。

## 3. 能力与限制

- 强制结束进程：`ZwOpenProcess` + `ZwTerminateProcess`；PPL/受保护进程会返回权限错误，不绕过。
- 强制删除文件：先 `ZwDeleteFile`；失败后用 `FILE_DISPOSITION_INFORMATION_EX` + POSIX 语义。
- 被其他进程独占打开（不允许 `FILE_SHARE_DELETE`）的文件仍可能返回共享冲突；驱动不会枚举/关闭任意进程句柄。
- 被映射文件通常可立即 unlink，已有映射继续有效直到最后一个句柄关闭。
- 生产分发需要 WHQL/attestation 签名；本包只提供测试签名脚本。

## 4. 强制安全约束

1. **绝不在宿主机加载 `HipsDriver.sys`。**
2. 只在独立 VM + 测试签名 + 可回滚快照中验证。
3. VM 测试时关闭共享文件夹、拖放、剪贴板、网络、VMCI 等宿主通道。
4. 任何执行动作都应由用户态明确请求，并记录审计日志。
5. 驱动崩溃不能导致用户数据损坏；测试前先做快照。

## 5. 建议落地顺序

1. 用户态服务：文件事件订阅、扫描队列、隔离、日志；
2. minifilter 只观察不阻断；
3. 测试签名驱动在 VM 验证蓝屏/死锁/卸载；
4. 再接入强杀/强删/自保护；
5. 最后做 WHQL/attestation 与正式分发。
