/* HipsDriver.c -- 最小 HIPS 内核执行端
 *
 * 只做三件事：
 *   1. 创建 \Device\HipsDriver，ACL 仅允许 SYSTEM；
 *   2. IOCTL 强制结束进程（ZwOpenProcess + ZwTerminateProcess）；
 *   3. IOCTL 强制删除文件（ZwDeleteFile，失败后 POSIX disposition）。
 *
 * 不做：任意内核读写、任意进程内存读写、句柄枚举、实时监控。
 * 所有动作都必须由 SYSTEM 用户态显式请求，并由调用方记录审计日志。
 */
#include <ntifs.h>
#include <wdmsec.h>

#include "HipsDriver.h"

#define HIPS_DRIVER_VERSION_MAJOR 1
#define HIPS_DRIVER_VERSION_MINOR 0
#define HIPS_DRIVER_VERSION_BUILD 0

/* 内核头文件不导出 winnt.h 的进程访问常量；PROCESS_TERMINATE 固定为 0x0001。 */
#ifndef PROCESS_TERMINATE
#  define PROCESS_TERMINATE 0x0001
#endif

/* 仅用于允许管理员通过设备类策略进一步收紧 ACL；不是设备本身的 ACL。 */
static const GUID g_HipsDeviceClassGuid =
    {0x5b3e2f1a, 0x7c4d, 0x4e2b, {0x9a, 0x11, 0x3c, 0x5d, 0x6e, 0x7f, 0x80, 0x91}};

/* 设备 ACL：只有 SYSTEM (S-1-5-18) 拥有 GA（GENERIC_ALL）。 */
DECLARE_CONST_UNICODE_STRING(g_HipsSddl, L"D:P(A;;GA;;;SY)");

static PDEVICE_OBJECT g_HipsDevice = NULL;

static NTSTATUS HipsCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS HipsTerminateProcess(ULONG pid, ULONG exit_code) {
    CLIENT_ID cid;
    OBJECT_ATTRIBUTES oa;
    HANDLE process = NULL;
    NTSTATUS status;

    /* 0 = Idle，4 = System；拒绝这两个 PID，避免把系统打挂。 */
    if (pid == 0 || pid == 4) return STATUS_INVALID_PARAMETER;

    cid.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
    cid.UniqueThread = NULL;
    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwOpenProcess(&process, PROCESS_TERMINATE, &oa, &cid);
    if (!NT_SUCCESS(status)) return status;

    status = ZwTerminateProcess(process, (NTSTATUS)exit_code);
    ZwClose(process);
    return status;
}

static BOOLEAN HipsPrefix(const WCHAR *s, const WCHAR *prefix, ULONG chars) {
    ULONG i;
    for (i = 0; i < chars; i++) {
        if (s[i] != prefix[i]) return FALSE;
    }
    return TRUE;
}

static BOOLEAN HipsPathLooksAbsolute(const WCHAR *path) {
    if (!path) return FALSE;
    /* 只接受 NT 绝对路径，避免把相对路径解释到 System32。 */
    if (path[0] != L'\\') return FALSE;
    if (path[1] == L'\\' && path[2] == L'?' && path[3] == L'?' && path[4] == L'\\') return TRUE;
    if (HipsPrefix(path, L"\\Device\\", 8)) return TRUE;
    return FALSE;
}

static BOOLEAN HipsPathIsTerminated(const WCHAR *path) {
    ULONG i;
    if (!path) return FALSE;
    for (i = 0; i < HIPS_MAX_PATH; i++) {
        if (path[i] == L'\0') return TRUE;
    }
    return FALSE;
}

static NTSTATUS HipsDeleteFile(const WCHAR *path) {
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE file = NULL;
    NTSTATUS status;

    if (!HipsPathLooksAbsolute(path) || !HipsPathIsTerminated(path))
        return STATUS_INVALID_PARAMETER;

    RtlInitUnicodeString(&name, path);
    InitializeObjectAttributes(&oa, &name,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL, NULL);

    /* 快路径：直接删除。 */
    status = ZwDeleteFile(&oa);
    if (NT_SUCCESS(status)) return status;

    /* 慢路径：带 DELETE + 全共享打开，再用 POSIX disposition。
     * POSIX 语义会立即从命名空间移除，已打开的句柄仍可继续使用；
     * 对“文件被映射/被占用”的场景比 ZwDeleteFile 更稳。 */
    InitializeObjectAttributes(&oa, &name,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL, NULL);
    status = ZwOpenFile(&file,
                        DELETE | SYNCHRONIZE,
                        &oa,
                        &iosb,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_OPEN_FOR_BACKUP_INTENT | FILE_OPEN_REPARSE_POINT);
    if (!NT_SUCCESS(status)) return status;

    {
        FILE_DISPOSITION_INFORMATION_EX disp_ex;
        disp_ex.Flags = FILE_DISPOSITION_DELETE | FILE_DISPOSITION_POSIX_SEMANTICS;
        status = ZwSetInformationFile(file, &iosb, &disp_ex, sizeof(disp_ex),
                                      FileDispositionInformationEx);
        if (!NT_SUCCESS(status)) {
            FILE_DISPOSITION_INFORMATION disp;
            disp.DeleteFile = TRUE;
            status = ZwSetInformationFile(file, &iosb, &disp, sizeof(disp),
                                          FileDispositionInformation);
        }
    }

    ZwClose(file);
    return status;
}

static NTSTATUS HipsDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG code = irpSp->Parameters.DeviceIoControl.IoControlCode;
    ULONG in_len = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG out_len = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID buffer = Irp->AssociatedIrp.SystemBuffer;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG info = 0;

    UNREFERENCED_PARAMETER(DeviceObject);

    /* 破坏性 IOCTL 要求句柄具有写权限；ACL 已限制为 SYSTEM，这是第二道门。 */
    if (code == HIPS_IOCTL_TERMINATE_PROCESS || code == HIPS_IOCTL_DELETE_FILE) {
        status = IoValidateDeviceIoControlAccess(Irp, FILE_WRITE_ACCESS);
        if (!NT_SUCCESS(status)) goto done;
    }

    switch (code) {
    case HIPS_IOCTL_QUERY_VERSION: {
        PHIPS_VERSION_INFO vi;
        if (out_len < sizeof(HIPS_VERSION_INFO)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        vi = (PHIPS_VERSION_INFO)buffer;
        RtlZeroMemory(vi, sizeof(*vi));
        vi->Major = HIPS_DRIVER_VERSION_MAJOR;
        vi->Minor = HIPS_DRIVER_VERSION_MINOR;
        vi->Build = HIPS_DRIVER_VERSION_BUILD;
        {
            static const WCHAR tag[] = L"OpandaHIPS";
            RtlCopyMemory(vi->Tag, tag, sizeof(tag));
        }
        info = sizeof(*vi);
        status = STATUS_SUCCESS;
        break;
    }
    case HIPS_IOCTL_TERMINATE_PROCESS: {
        PHIPS_PROCESS_REQUEST req;
        if (in_len < sizeof(HIPS_PROCESS_REQUEST)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        req = (PHIPS_PROCESS_REQUEST)buffer;
        if (req->Size != sizeof(HIPS_PROCESS_REQUEST)) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        status = HipsTerminateProcess(req->ProcessId, req->ExitCode);
        break;
    }
    case HIPS_IOCTL_DELETE_FILE: {
        PHIPS_FILE_REQUEST req;
        if (in_len < sizeof(HIPS_FILE_REQUEST)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        req = (PHIPS_FILE_REQUEST)buffer;
        if (req->Size != sizeof(HIPS_FILE_REQUEST) || req->Flags != 0) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        status = HipsDeleteFile(req->Path);
        break;
    }
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

done:
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

static VOID HipsUnload(PDRIVER_OBJECT DriverObject) {
    UNICODE_STRING dos_name;
    RtlInitUnicodeString(&dos_name, HIPS_DOS_NAME);
    IoDeleteSymbolicLink(&dos_name);
    if (g_HipsDevice) {
        IoDeleteDevice(g_HipsDevice);
        g_HipsDevice = NULL;
    }
    UNREFERENCED_PARAMETER(DriverObject);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNICODE_STRING dev_name;
    UNICODE_STRING dos_name;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);

    RtlInitUnicodeString(&dev_name, HIPS_DEVICE_NAME);
    RtlInitUnicodeString(&dos_name, HIPS_DOS_NAME);

    status = IoCreateDeviceSecure(DriverObject,
                                  0,
                                  &dev_name,
                                  FILE_DEVICE_UNKNOWN,
                                  FILE_DEVICE_SECURE_OPEN,
                                  FALSE,
                                  &g_HipsSddl,
                                  &g_HipsDeviceClassGuid,
                                  &g_HipsDevice);
    if (!NT_SUCCESS(status)) return status;

    status = IoCreateSymbolicLink(&dos_name, &dev_name);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_HipsDevice);
        g_HipsDevice = NULL;
        return status;
    }

    g_HipsDevice->Flags |= DO_BUFFERED_IO;
    g_HipsDevice->Flags &= ~DO_DEVICE_INITIALIZING;

    DriverObject->MajorFunction[IRP_MJ_CREATE] = HipsCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = HipsCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = HipsDeviceControl;
    DriverObject->DriverUnload = HipsUnload;

    return STATUS_SUCCESS;
}
