/* HipsDriver.h -- 用户态/内核态共享 ABI
 *
 * 设备：\\.\HipsDriver
 * 访问：设备 ACL 仅允许 SYSTEM；用户态客户端必须以 SYSTEM 运行。
 */
#ifndef HIPS_DRIVER_H
#define HIPS_DRIVER_H

/* 内核侧由 HipsDriver.c 先包含 <ntifs.h>；这里不再重复包含 ntddk/ntifs，
 * 否则 PEPROCESS/PETHREAD 会因两个头文件的 typedef 不同而重定义。 */
#ifdef _KERNEL_MODE
/* keep the includer's kernel headers */
#else
#  include <windows.h>
#  include <winioctl.h>
#endif

#define HIPS_DEVICE_NAME    L"\\Device\\HipsDriver"
#define HIPS_DOS_NAME       L"\\DosDevices\\HipsDriver"
#define HIPS_USER_NAME      L"\\\\.\\HipsDriver"
#define HIPS_MAX_PATH       520

#define HIPS_IOCTL_QUERY_VERSION        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_READ_DATA)
#define HIPS_IOCTL_TERMINATE_PROCESS    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_WRITE_DATA)
#define HIPS_IOCTL_DELETE_FILE          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x902, METHOD_BUFFERED, FILE_WRITE_DATA)

typedef struct _HIPS_VERSION_INFO {
    ULONG Major;
    ULONG Minor;
    ULONG Build;
    WCHAR Tag[32];
} HIPS_VERSION_INFO, *PHIPS_VERSION_INFO;

typedef struct _HIPS_PROCESS_REQUEST {
    ULONG Size;        /* sizeof(HIPS_PROCESS_REQUEST) */
    ULONG ProcessId;
    ULONG ExitCode;    /* 传给 ZwTerminateProcess 的退出码 */
    ULONG Reserved;
} HIPS_PROCESS_REQUEST, *PHIPS_PROCESS_REQUEST;

typedef struct _HIPS_FILE_REQUEST {
    ULONG Size;        /* sizeof(HIPS_FILE_REQUEST) */
    ULONG Flags;       /* 保留，必须为 0 */
    WCHAR Path[HIPS_MAX_PATH]; /* NT 路径：\??\C:\... 或 \Device\... */
} HIPS_FILE_REQUEST, *PHIPS_FILE_REQUEST;

#endif /* HIPS_DRIVER_H */
