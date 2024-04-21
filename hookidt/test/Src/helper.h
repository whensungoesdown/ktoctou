#ifndef _HELPER_H_
#define _HELPER_H_
//-----------------------------------------------------------------------------//
typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER SpareLi1;
	LARGE_INTEGER SpareLi2;
	LARGE_INTEGER SpareLi3;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR PageDirectoryBase;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

#define SystemProcessInformation 0x5

typedef struct _KAPC_STATE
{
	LIST_ENTRY ApcListHead[2];
	PKPROCESS Process;
	UCHAR KernelApcInProgress;
	UCHAR KernelApcPending;
	UCHAR UserApcPending;
} KAPC_STATE, *PKAPC_STATE;
//-----------------------------------------------------------------------------//
extern ULONG g_TargetCr3;
//-----------------------------------------------------------------------------//
NTSTATUS
GetProcessCr3(HANDLE Pid, PULONG Cr3);

NTSTATUS FindTargetProcess();
//-----------------------------------------------------------------------------//
#endif // !_HELPER_H_
