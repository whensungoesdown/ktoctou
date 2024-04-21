#include <ntddk.h>
#include "helper.h"
//-----------------------------------------------------------------------------//
ULONG g_TargetCr3 = 0;
ULONG g_TargetKprcb = 0;
ULONG g_TargetEprocess = 0;
//-----------------------------------------------------------------------------//
NTSTATUS
GetProcessCr3(HANDLE Pid, PULONG Cr3, PULONG Eprocess)
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
	*Eprocess = pEprocess;

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

		DbgPrint("ImageName: %S\n", pProcessInfo->ImageName.Buffer);

		if ((NULL != pProcessInfo->ImageName.Buffer) && (0 == wcsncmp(/*L"testxxx"*/ L"notepad", pProcessInfo->ImageName.Buffer, 7)))
		{
			ULONG ulCr3 = 0;
			ULONG ulKprcb = 0;
			ULONG ulEprocess = 0;

			GetProcessCr3(pProcessInfo->UniqueProcessId, &ulCr3, &ulEprocess);

			g_TargetCr3 = ulCr3;

			__asm
			{
				mov eax, fs:0x20
				mov ulKprcb, eax
			}

			g_TargetKprcb = ulKprcb;

			g_TargetEprocess = ulEprocess;

			DbgPrint("%S,  0x%x, kprcb 0x%x\n", pProcessInfo->ImageName.Buffer, ulCr3, g_TargetKprcb);
		}

		pProcessInfo = (PSYSTEM_PROCESS_INFORMATION)((PCHAR)pProcessInfo + pProcessInfo->NextEntryOffset);
	}

	Status = STATUS_SUCCESS;
//Exit0:
	return Status;
}
//-----------------------------------------------------------------------------//
#define Naked   __declspec( naked ) 

ULONG MaskTable[518] =
{
	0x00004000, 0x00004000, 0x00004000, 0x00004000,
	0x00008000, 0x00008000, 0x00000000, 0x00000000,
	0x00004000, 0x00004000, 0x00004000, 0x00004000,
	0x00008000, 0x00008000, 0x00000000, 0x00000000,
	0x00004000, 0x00004000, 0x00004000, 0x00004000,
	0x00008000, 0x00008000, 0x00000000, 0x00000000,
	0x00004000, 0x00004000, 0x00004000, 0x00004000,
	0x00008000, 0x00008000, 0x00000000, 0x00000000,
	0x00004000, 0x00004000, 0x00004000, 0x00004000,
	0x00008000, 0x00008000, 0x00000008, 0x00000000,
	0x00004000, 0x00004000, 0x00004000, 0x00004000,
	0x00008000, 0x00008000, 0x00000008, 0x00000000,
	0x00004000, 0x00004000, 0x00004000, 0x00004000,
	0x00008000, 0x00008000, 0x00000008, 0x00000000,
	0x00004000, 0x00004000, 0x00004000, 0x00004000,
	0x00008000, 0x00008000, 0x00000008, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00004000, 0x00004000,
	0x00000008, 0x00000008, 0x00001008, 0x00000018,
	0x00002000, 0x00006000, 0x00000100, 0x00004100,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000100, 0x00000100, 0x00000100, 0x00000100,
	0x00000100, 0x00000100, 0x00000100, 0x00000100,
	0x00000100, 0x00000100, 0x00000100, 0x00000100,
	0x00000100, 0x00000100, 0x00000100, 0x00000100,
	0x00004100, 0x00006000, 0x00004100, 0x00004100,
	0x00004000, 0x00004000, 0x00004000, 0x00004000,
	0x00004000, 0x00004000, 0x00004000, 0x00004000,
	0x00004000, 0x00004000, 0x00004000, 0x00004000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00002002, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000020, 0x00000020, 0x00000020, 0x00000020,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000100, 0x00002000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000100, 0x00000100, 0x00000100, 0x00000100,
	0x00000100, 0x00000100, 0x00000100, 0x00000100,
	0x00002000, 0x00002000, 0x00002000, 0x00002000,
	0x00002000, 0x00002000, 0x00002000, 0x00002000,
	0x00004100, 0x00004100, 0x00000200, 0x00000000,
	0x00004000, 0x00004000, 0x00004100, 0x00006000,
	0x00000300, 0x00000000, 0x00000200, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00004000, 0x00004000, 0x00004000, 0x00004000,
	0x00000100, 0x00000100, 0x00000000, 0x00000000,
	0x00004000, 0x00004000, 0x00004000, 0x00004000,
	0x00004000, 0x00004000, 0x00004000, 0x00004000,
	0x00000100, 0x00000100, 0x00000100, 0x00000100,
	0x00000100, 0x00000100, 0x00000100, 0x00000100,
	0x00002000, 0x00002000, 0x00002002, 0x00000100,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000008, 0x00000000, 0x00000008, 0x00000008,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00004000, 0x00004000,
	0x00004000, 0x00004000, 0x00004000, 0x00004000,
	0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0x00002000, 0x00002000, 0x00002000, 0x00002000,
	0x00002000, 0x00002000, 0x00002000, 0x00002000,
	0x00002000, 0x00002000, 0x00002000, 0x00002000,
	0x00002000, 0x00002000, 0x00002000, 0x00002000,
	0x00004000, 0x00004000, 0x00004000, 0x00004000,
	0x00004000, 0x00004000, 0x00004000, 0x00004000,
	0x00004000, 0x00004000, 0x00004000, 0x00004000,
	0x00004000, 0x00004000, 0x00004000, 0x00004000,
	0x00000000, 0x00000000, 0x00000000, 0x00004000,
	0x00004100, 0x00004000, 0xFFFFFFFF, 0xFFFFFFFF,
	0x00000000, 0x00000000, 0x00000000, 0x00004000,
	0x00004100, 0x00004000, 0xFFFFFFFF, 0x00004000,
	0x00004000, 0x00004000, 0x00004000, 0x00004000,
	0x00004000, 0x00004000, 0x00004000, 0x00004000,
	0xFFFFFFFF, 0xFFFFFFFF, 0x00004100, 0x00004000,
	0x00004000, 0x00004000, 0x00004000, 0x00004000,
	0x00004000, 0x00004000, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0x00000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF
};

Naked ULONG GetOpCodeSize_ASM_CODE(PVOID Start, PVOID Tlb)
{
	__asm {
		pushad
		mov   esi, [esp + 24h]
		mov   ecx, [esp + 28h]
		xor edx, edx
		xor   eax, eax
		L005 :
		and   dl, 0F7h
			mov   al, [ecx]
			inc   ecx
			or edx, [esi + eax * 4h]
			test   dl, 8h
			jnz L005
			cmp   al, 0F6h
			je L035
			cmp   al, 0F7h
			je L035
			cmp   al, 0CDh
			je L040
			cmp   al, 0Fh
			je L045
			L019 :
		test   dh, 80h
			jnz L052
			L021 :
		test   dh, 40h
			jnz L067
			L023 :
		test   dl, 20h
			jnz L057
			L025 :
		test   dh, 20h
			jnz L062
			L027 :
		mov   eax, ecx
			sub   eax, [esp + 28h]
			and edx, 707h
			add   al, dl
			add   al, dh
			L032 :
		mov[esp + 1Ch], eax
			popad
			retn
			L035 :
		or dh, 40h
			test   byte ptr[ecx], 38h
			jnz L019
			or dh, 80h
			jmp L019
			L040 :
		or dh, 1h
			cmp   byte ptr[ecx], 20h
			jnz L019
			or dh, 4h
			jmp L019
			L045 :
		mov   al, [ecx]
			inc   ecx
			or edx, [esi + eax * 4h + 400h]
			cmp   edx, -1h
			jnz L019
			mov   eax, edx
			jmp L032
			L052 :
		xor   dh, 20h
			test   al, 1h
			jnz L021
			xor   dh, 21h
			jmp L021
			L057 :
		xor   dl, 2h
			test   dl, 10h
			jnz L025
			xor   dl, 6h
			jmp L025
			L062 :
		xor   dh, 2h
			test   dh, 10h
			jnz L027
			xor   dh, 6h
			jmp L027
			L067 :
		mov   al, [ecx]
			inc   ecx
			mov   ah, al
			and   ax, 0C007h
			cmp   ah, 0C0h
			je L023
			test   dl, 10h
			jnz L090
			cmp   al, 4h
			jnz L080
			mov   al, [ecx]
			inc   ecx
			and   al, 7h
			L080 :
		cmp   ah, 40h
			je L088
			cmp   ah, 80h
			je L086
			cmp   ax, 5h
			jnz L023
			L086 :
		or dl, 4h
			jmp L023
			L088 :
		or dl, 1h
			jmp L023
			L090 :
		cmp   ax, 6h
			je L096
			cmp   ah, 40h
			je L088
			cmp   ah, 80h
			jnz L023
			L096 :
		or dl, 2h
			jmp L023
			retn
	}
}

ULONG GetOpCodeSize(PVOID Start)
{
	__asm
	{
		push Start
		push offset MaskTable
		call GetOpCodeSize_ASM_CODE
		add   esp, 8
	}
}
//-----------------------------------------------------------------------------//