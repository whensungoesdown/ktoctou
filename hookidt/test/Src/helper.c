#include <ntddk.h>
#include "helper.h"
//-----------------------------------------------------------------------------//
ULONG g_TargetCr3 = 0;
ULONG g_TargetKprcb = 0;
//-----------------------------------------------------------------------------//
NTSTATUS
GetProcessCr3(HANDLE Pid, PULONG Cr3)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	PEPROCESS pEprocess = NULL;

	KAPC_STATE ApcState;

	ULONG ulCr3 = 0;

	Status = PsLookupProcessByProcessId(Pid, &pEprocess);
	if (STATUS_SUCCESS != Status)
	{
		return Status;
	}

	KeStackAttachProcess(pEprocess, &ApcState);

	__asm
	{
		mov eax, cr3
		mov ulCr3, eax
	}

	*Cr3 = ulCr3;

	KeUnstackDetachProcess(&ApcState);

	ObDereferenceObject(pEprocess);
}
//-----------------------------------------------------------------------------//
NTSTATUS FindTargetProcess()
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	PSYSTEM_PROCESS_INFORMATION pProcessInfo = NULL;
	ULONG ulBufferSize = 0;

	//__asm int 3;

	Status = ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &ulBufferSize);
	if (!NT_SUCCESS(Status) && (STATUS_INFO_LENGTH_MISMATCH != Status))
	{
		return Status;
	}

	// for new processes that just created
	ulBufferSize += 0x200;

	pProcessInfo = (PSYSTEM_PROCESS_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, ulBufferSize, 'htdi');
	if (NULL == pProcessInfo)
	{
		return STATUS_UNSUCCESSFUL;
	}

	Status = ZwQuerySystemInformation(SystemProcessInformation, pProcessInfo, ulBufferSize, NULL);

	while (TRUE)
	{

		if (0 == pProcessInfo->NextEntryOffset)
		{
			break;
		}

		if ((NULL != pProcessInfo->ImageName.Buffer) && (0 == wcsncmp(L"testxxx", pProcessInfo->ImageName.Buffer, 7)))
		{
			ULONG ulCr3 = 0;
			ULONG ulKprcb = 0;

			GetProcessCr3(pProcessInfo->UniqueProcessId, &ulCr3);

			g_TargetCr3 = ulCr3;

			__asm
			{
				mov eax, fs:0x20
				mov ulKprcb, eax
			}

			g_TargetKprcb = ulKprcb;

			DbgPrint("%S,  0x%x, kprcb 0x%x\n", pProcessInfo->ImageName.Buffer, ulCr3, g_TargetKprcb);
		}

		pProcessInfo = (PSYSTEM_PROCESS_INFORMATION)((PCHAR)pProcessInfo + pProcessInfo->NextEntryOffset);
	}

	Status = STATUS_SUCCESS;
//Exit0:
	return Status;
}
//-----------------------------------------------------------------------------//