Opanda HIPS / GUI / PE_VM VM 测试说明
====================================

安全边界
--------
1. 本 ISO 只包含本项目自己编译的良性测试程序，不包含任何恶意样本。
2. 测试前请确认 VM 已关闭：
   - 共享文件夹 / HGFS
   - 拖放 / 剪贴板
   - NAT / 桥接 / 仅主机网络
   - 声音、3D 加速、VMCI、VMware Tools 自动安装
3. 建议从干净快照启动；测试结束后回滚快照。

一、GUI / 硬件检测 / PE_VM
--------------------------
1. 在 VM 内打开光驱，双击 run_tests.cmd。
   它会把文件复制到 C:\opanda_test，并输出 results.txt。
2. 双击 run_gui.cmd，检查：
   - 左侧只有 5 项：安全性概览、病毒和威胁防护、隔离区、保护历史记录、安全设置
   - 全局黑/白/灰，无彩色文字
   - Windows 11 下窗口为原生圆角（DWM）
   - 安全性概览的“硬件环境检测”显示 SGX / PT / TPM 2.0 / 虚拟化环境
3. results.txt 里应包含 hw_probe 的 SGX/PT/TPM/Hypervisor 结果，以及
   pe_vm 的 selftest 和 JMP [IAT] 测试输出。

二、HIPS 驱动
-------------
前置：VM 必须关闭 Secure Boot，且允许测试签名。
1. 以管理员身份运行 driver_test.cmd：
   - 导入 OpandaTest.cer 到 Root / TrustedPublisher
   - bcdedit /set testsigning on
   - 安装并启动 HipsDriver 服务
2. 如果 sc start 返回 577/1275，重启 VM 后再次运行 driver_test.cmd。
3. 驱动启动后，以管理员身份运行 driver_full_test.cmd：
   - 启动 HipsTestTarget.exe（创建并映射一个测试文件）
   - 以 SYSTEM 计划任务运行 HipsClient.exe delete <文件>
   - 以 SYSTEM 计划任务运行 HipsClient.exe kill <PID>
   - 检查 hips_delete.txt / hips_kill.txt

注意：
- 设备 ACL 只允许 SYSTEM；管理员直接运行 HipsClient.exe 会被拒绝，
  必须通过计划任务 / 服务以 SYSTEM 运行。
- 如果删除返回共享冲突，说明目标句柄未允许 DELETE 共享；
  这是 Windows 的正常限制，不是驱动崩溃。
- 绝不在宿主机加载 HipsDriver.sys。

三、文件清单
------------
ScannerUI.exe            新 GUI
scanner.dll              带 scanner_get_hardware_info 的引擎
scaler.txt / signatures.db
hw_probe.exe             硬件检测验证
pe_vm_msvc.exe           MSVC 构建的 PE_VM
pe_vm.exe                旧版 PE_VM（对照）
pevm_jmp_test.exe        良性 JMP [IAT] 测试 PE
HipsDriver.sys           测试签名驱动
HipsDriver.inf
HipsClient.exe           用户态调用示例
HipsTestTarget.exe       良性占用/映射测试目标
OpandaTest.cer           测试证书公钥
run_tests.cmd / run_gui.cmd
driver_test.cmd / driver_full_test.cmd
