Copyright (C) opanda Technology Co., Ltd. All rights reserved.

恶意软件扫描器 · 交付包
========================

快速启动：
  双击 start_gui.cmd

直接运行：
  bin\ScannerUI.exe

详细说明：
  docs\README_CN.md
  docs\GUI.md
  docs\SCANNER_DLL.md
  docs\TEST_REPORT.md
  docs\DRIVER_BOUNDARY.md

自检：
  cd bin
  scanner_test.exe "C:\path\to\sample.exe"

注意：
  · 静态扫描，不执行样本。
  · 当前不含服务、实时监控或未签名驱动。
  · 隔离文件按原文件保存（.qtn），未加密。
  · 正式分发前请做 Authenticode 签名。





旧版进展-----to lamio



Objective
明早前交付完整 scanner.dll + signatures.db 病毒库 + WD 风格 GUI；用户不在电脑旁，要求自主排查并按最优方案推进。
Requirements
用户原话：“我一会不会守在电脑边，你自己忙，总之明天早上交付完整dll＋db病毒库，和WD风格GUI，自己排查，另外有问题按照你自己的最优方法走”。
GUI：极简、毛玻璃半透明、大圆角卡片、柔和阴影、平滑过渡、自适应深浅色、侧边导航、强调色、卡片布局。
静态扫描绝不执行样本；全中文；保留 [HIGH RISK / [SUSPICIOUS / [NORMAL] / [TRUSTED / [PACKED / [SKIP、File appears to be PACKED、== 汇总: ... ==、阈值 ≥80/≥50。
交付约定：cmd 启动器 GBK+CRLF；txt/ps1/md UTF-8+BOM；.ps1 兼容 PS 5.1；拷贝后 SHA256 校验；解压默认密码 infected；PS 脚本内不设 [Console]::OutputEncoding = UTF8。
目录/文件名用 ASCII；特征码集成 .db；所有对话与思考链使用中文。
驱动签名/WHQL 由用户负责；不要动 E 盘两台 Hyper-V 分析机，不写 Hyper-V 调度代码。
驱动边界：只做机制不做判定；不暴露任意内核读写；设备 ACL 只允许 SYSTEM；必须提供维护模式卸载。
Decisions
DLL 使用 C ABI + 固定长度 ScannerResult，统一复用 scan_one_file()；外部 .db 优先于内置 53 条表。
GUI 采用 Win32 + Direct2D/DirectWrite 自绘，运行时 LoadLibraryW("scanner.dll") + GetProcAddress。
GUI 使用 PerMonitorV2，按真实 DPI 绘制；窗口基准 1180×640 DIPs，鼠标坐标由物理像素转 DIPs 后命中测试。
每帧先 ID2D1HwndRenderTarget::Clear(theme.bg1)，避免 DWM/Acrylic 下透明导致“只剩文字”。
结果评分显示规则：<10 显示两位小数，≥10 显示一位小数（如 0.24、100.0）。
扫描结束后自动选中最高等级结果；隔离区加载/进入页面后自动选中第一项，恢复/删除按钮立即可用。
隔离索引补齐 SHA256：DLL 在特征码命中与 [PACKED] 命中时也计算 SHA；GUI 已确认写入 index.tsv。
表格结论列加宽到能完整显示 [HIGH RISK - SIGNATURE]；设置页路径/按钮、关于页按钮重叠已修复。
驱动页移除会遮挡说明文字的禁用“安装驱动”按钮；驱动安装仍不在本轮交付内。
SQLite 迁移暂缓，当前文本 .db 满足轻量化交付。
Work State
Completed
全部 C 扫描源码可编译；DLL 化、外部特征库、53 条 signatures.db、回归测试、DLL 构建脚本已通过。
scan_main.c 已修复特征码/加壳路径不写 SHA 的问题；新 DLL 已生成并复制到 gui\scanner.dll。
新 DLL SHA256：9A3C687FE3206D0D79C7E666E2B4795AB057DED144958A12F4FB81095A46EF53；旧 FA77... 已过期。
666.exe 已验证为正常结果，分数曾显示 0.2；已改为两位小数，待最终复核显示 0.24。
Phobos 已验证：[HIGH RISK - SIGNATURE]、100 分、红色结果、Ransom.Win32.Phobos、自动选中、隔离选中/打开位置启用。
隔离流程已验证：文件移动成功，quarantine/index.tsv 写入完整 SHA；隔离后结果行显示“已隔离”；隔离区计数徽标更新。
恢复流程已验证：恢复后样本回到原路径，索引变为仅 BOM（3 字节）。
隔离区页面已验证：自动选中首项、恢复/删除按钮启用、[HIGH RISK - SIGNATURE] 不再截断、选中行高亮。
日志页面已验证：高危与 [SCAN] 记录显示正常，结论 chip 完整，评分列对齐，清空按钮可用。
防护页截图正常；主页/扫描页/隔离区/日志/设置/深色主题均已截图检查。
设置页已修复病毒库路径与按钮重叠、关于页说明与按钮重叠；深色主题切换成功并落盘。
驱动页已发现并修复“安装驱动”禁用按钮与说明文字重叠的问题；已重新编译，待重新截图确认。
--scan <path> 与 --page scan|protection|quarantine|logs|driver|settings 可用。
快速扫描标签已改为“快速扫描：桌面、下载、临时目录、启动项”，避免沿用上一次扫描路径。
scanner_apply_pending() 的 skipped 增量已修复，并被 GUI 使用。
已创建小样本目录 C:\Users\17265\AppData\Local\Temp\scanner_gui_test，含 666、Phobos、notepad、scan_any.ps1；尚未扫描测试。
Active
扫描 scanner_gui_test，验证多结果列表、滚动、选中、隔离按钮与结果排序。
重新验证 666 显示为 0.24，并复跑 scanner_test.exe 确认 db=53、score=0.24 未回归。
测试永久删除隔离项、日志刷新/清空、打开日志目录。
复测设置页浅色/系统主题、动画开关、最大文件大小、病毒库重载、打开数据目录。
复测驱动页去按钮后的布局；测试最小窗口、拖放、取消扫描、无 DLL 启动、退出时线程回收。
清理测试数据：历史记录、深色设置、隔离区空索引、shot_*.png、build_err*.txt、dll_build_err.txt、layout.log、log_debug()、scanner_gui_test。
新建 build\build_gui.ps1，包含 windres 与当前 g++ 命令，产出 ScannerUI.exe。
同步 scanner.dll、ScannerUI.exe、GUI 源码、manifest、rc、sdk\scanner_api.h 到最终交付目录。
重新生成 UTF-8 BOM 的 SHA256SUMS.txt，更新 VERSION.txt、docs 与最终清单。
更新过时文档：41 批次复核说明、静态漏检清单.txt、扩展扫描说明.md。
Blocked
驱动开发依赖 WHQL/attestation 签名与 minifilter altitude；签名用户负责，altitude 未确认。
驱动只宜在独立测试机验证，不能碰 E 盘 Hyper-V 分析机。
signatures.db 仍是文本格式；SQLite 迁移暂缓。
Next Move
扫描测试目录并检查多行结果、滚动、选中、隔离与结果排序。
复测 666 分数显示与 scanner_test.exe 的 db=53/score=0.24。
测试永久删除、日志清空、打开目录；复测浅色/系统主题及各项设置。
复测驱动页布局、最小窗口、拖放、取消、无 DLL 启动、退出线程回收。
移除 log_debug、调试日志、截图与构建错误文件，回到系统主题并清空历史/隔离测试数据。
新增 GUI 构建脚本并完成最终编译；同步源码、DLL、EXE、manifest、rc、SDK 头到交付目录。
重建 SHA256SUMS.txt 并更新版本/文档，最后从交付目录做一次独立启动与扫描验收。
Relevant Files
F:\SVM项目\04_c\gui\ui.cpp：全部页面绘制、表格列宽、设置/隔离/驱动页布局与交互。
F:\SVM项目\04_c\gui\main.cpp：Win32 窗口、D2D/DWrite、DPI/manifest、CLI 参数、临时鼠标/尺寸日志。
F:\SVM项目\04_c\gui\scan.cpp：DLL 加载、扫描线程、自动选中、历史/隔离区/设置/驱动状态。
F:\SVM项目\04_c\gui\app.h：App 状态、Gfx 资源、页面/扫描/历史结构。
F:\SVM项目\04_c\gui\theme.h：WD 风格浅色/深色色板。
F:\SVM项目\04_c\gui\ScannerUI.manifest：PerMonitorV2、comctl32 v6、asInvoker。
F:\SVM项目\04_c\gui\ScannerUI.rc：manifest 资源脚本。
F:\SVM项目\04_c\scan_main.c：扫描主流程；已修复特征码/加壳结果 SHA。
F:\SVM项目\04_c\scanner_api.c：DLL 入口、外部 db 自动加载、串行锁。
F:\SVM项目\04_c\scanner_api.h：DLL C ABI 与 ScannerResult 固定布局。
F:\SVM项目\04_c\signature_scan.c：外部 db 加载/导出/清空、特征匹配。
C:\Users\17265\Desktop\恶意软件扫描器\最终交付\：交付根目录。
C:\Users\17265\Desktop\恶意软件扫描器\最终交付\build\build_scanner_dll.ps1：DLL 构建脚本，需继续复用并同步最新源码。
C:\Users\17265\Desktop\恶意软件扫描器\样本集\：回归样本；Phobos 已恢复。
C:\Users\17265\AppData\Local\Temp\scanner_gui_test\：新建小样本测试目录，待扫描。
Important Context
GUI 编译命令：g++ -std=c++17 -O2 -municode -mwindows -static -static-libgcc -static-libstdc++ -finput-charset=UTF-8 -I.. main.cpp scan.cpp ui.cpp ScannerUI.res.o -o ScannerUI.exe -ld2d1 -ldwrite -ldwmapi -lole32 -luuid -lshell32 -lshlwapi -lcomctl32 -lcomdlg32 -luser32 -lgdi32 -ladvapi32。
DLL 编译命令已在工作区执行：gcc -shared -Os -s -static -DSCANNER_BUILD_DLL -o gui\scanner.dll ... '-Wl,--out-implib=libscanner.a' ...；PowerShell 中 -Wl,--out-implib=... 必须加引号。
manifest 编译：windres ScannerUI.rc -O coff -o ScannerUI.res.o，需 G:\mingw64\bin 在 PATH。
PowerShell 截图/鼠标脚本必须先调用 SetThreadDpiAwarenessContext(-4)；否则坐标被虚拟化到 1280×720，SetCursorPos 会被钳制，导致点击失效。
实际屏幕 1920×1080、DPI 144；GUI 窗口约 1770×960，客户区 1748×904（1165.3×602.7 DIPs）。
已用真实鼠标点击默认窗口的“隔离选中”屏幕坐标约 (1411,634)；隔离区“恢复选中”约 (670,238)。
layout.log 仍含 Gfx::resize、LBUTTONDOWN、LBUTTONUP 调试输出；log_debug() 必须交付前移除。
当前设置已切换为深色并持久化；打包前应恢复 System/浅色或删除 config\settings.ini。
当前历史记录含多次测试条目（至少 4 条 Phobos/666），打包前需清空 logs\history.tsv。
quarantine/index.tsv 当前仅 BOM（3 字节），隔离目录为空；Phobos 已恢复至样本集。
测试目录中 signatures.db 路径当前显示为 F:\SVM项目\04_c\gui\db\signatures.db，DB 仍为 53 条。
交付 EXE 与 DLL 尚未同步到最终交付目录；SHA256SUMS.txt 仍是旧哈希，必须重建。
已按“先保证能跑、再清理交付”的方式完成，主交付目录：

C:\Users\17265\Desktop\MalwareScanner_Release
旧路径 C:\Users\17265\Desktop\恶意软件扫描器\最终交付 也已同步成同一版本；原里程碑 1 目录备份为 final_delivery_milestone1_backup。

交付内容
文件	说明
bin\ScannerUI.exe	WD 风格 GUI，Win32 + Direct2D/DirectWrite
bin\scanner.dll	扫描引擎，C ABI，复用 scan_one_file()
db\signatures.db	外部特征库，53 条，UTF-8 文本
bin\scanner_test.exe	最小调用示例/自检
bin\sigdb_builder.exe	内置特征导出工具
bin\scaler.txt	模型标准化参数
sdk\scanner_api.h	C ABI 头文件
src\、src\gui\	可重建源码快照
build\	DLL、GUI、全量重建脚本
docs\	DLL、GUI、验证记录、驱动边界说明
start_gui.cmd	GUI 启动器，GBK + CRLF
已验证
666.exe → [NORMAL]，评分 0.24
Phobos → [HIGH RISK - SIGNATURE]，100，Ransom.Win32.Phobos
notepad.exe → [TRUSTED]
scan_any.ps1 → [SUSPICIOUS - SCRIPT]，55，Trojan.Script.Dropper
文件夹递归、结果自动选中、滚动、取消扫描
隔离 → .qtn 保存，索引写入 SHA256 → 恢复回原路径
日志、深浅色/跟随系统、设置持久化
缺少 scanner.dll 时明确报错，不静默失败
外部病毒库热重载、中文路径扫描正常
最终校验值
ScannerUI.exe   587DBAAFE6A95A63E900D2B438CCA90EA94A08A558F8C7BF32AF93F6F9E286C0
scanner.dll     5E796C9CAD86FEF51E9BF79B5A4AED32326535CC8A1A08EFA6265938281B0B45
signatures.db   E32A9DF3AD5A354BAD80511713983AB8F4EC43518DCF7CAF6D981649D30591DD
SHA256SUMS.txt 已包含全部 52 个交付文件，逐项复核结果：0 个缺失、0 个不匹配。

使用
双击根目录 start_gui.cmd，或直接运行：

bin\ScannerUI.exe
自检：

cd bin
scanner_test.exe "C:\path\to\sample.exe"
边界说明
静态扫描，不执行样本；pe_vm 在 DLL 模式强制关闭。
当前不包含实时监控、服务、强杀/强删、自保护驱动；驱动签名与 WHQL 由你方负责，包内没有未签名驱动二进制。
隔离文件按原文件保存为 .qtn，未加密；建议放在受控目录。
当前未做 Authenticode 签名，正式分发前需要签名。
signatures.db 目前是 53 条文本特征库，不是 SQLite；后续迁移可保持 ABI 不变。