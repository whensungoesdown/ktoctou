#include <ntddk.h>
#include "structs.h"
#include "smap.h"
#include "idthook.h"
//-----------------------------------------------------------------------------//
ULONG originalIDT2eISR;

PIDT_DESCRIPTOR id0eAddr[MAX_NUMBER_OF_CPUS];
//-----------------------------------------------------------------------------//
__declspec(naked) void PageFaultHandler()
{
	__asm
	{
		// Before calling kernel functions,
		// fs should be set to 0x30
		//__asm int 3;

		pushad;
		pushfd;
		push fs;
		mov bx, 0x30;
		mov fs, bx;

		//push edx;
		//push eax;
		//__asm int 3;

		call HandleSmap;

		cmp eax, 0
		je pass

		pop fs;
		popfd;
		popad;
		add esp, 4
		iretd

	pass:

		pop fs;
		popfd;
		popad;
		jmp originalIDT2eISR;
	}
}
//-----------------------------------------------------------------------------//
DWORD makeDWORD(WORD hi, WORD lo)
{
	DWORD value = 0;
	value = value | (DWORD)hi;
	value <<= 16;
	value = value | (DWORD)lo;
	return value;
}
//-----------------------------------------------------------------------------//
void HookCPU(DWORD dwProcAddress)
{
	DWORD dwIndex;
	PKTHREAD pkThread;
	KAFFINITY cpuBitMap;
	UNICODE_STRING usKeSetAffinityThread;
	KeSetAffinityThreadPtr KeSetAffinityThread;

	KdPrint(("[HookCPU]\n"));

	pkThread = KeGetCurrentThread();
	cpuBitMap = KeQueryActiveProcessors();
	RtlInitUnicodeString(&usKeSetAffinityThread, L"KeSetAffinityThread");
	KeSetAffinityThread = (KeSetAffinityThreadPtr)MmGetSystemRoutineAddress(&usKeSetAffinityThread);

	for (dwIndex = 0; dwIndex < MAX_NUMBER_OF_CPUS; ++dwIndex)
	{
		KAFFINITY currentCPU = cpuBitMap & (1 << dwIndex);
		if (currentCPU != 0)
		{
			IDTR idtr;
			PIDT_DESCRIPTOR idt;
			DWORD idt2e;

			KeSetAffinityThread(pkThread, currentCPU);

			if (id0eAddr[dwIndex] == 0)
			{
				__asm sidt idtr
				idt = (PIDT_DESCRIPTOR)makeDWORD((WORD)idtr.BaseHi, (WORD)idtr.BaseLo);
				id0eAddr[dwIndex] = idt + SYSTEM_SERVICE_VECTOR;
				if (originalIDT2eISR == 0)
					originalIDT2eISR = makeDWORD(id0eAddr[dwIndex]->offset16_31, id0eAddr[dwIndex]->offset00_15);
				KdPrint(("IDT: 0x%08X, originalIDT2eISR: 0x%08X\n", (DWORD)idt, originalIDT2eISR));
			}
			idt2e = (DWORD)id0eAddr[dwIndex];

			__asm
			{
				cli;
				mov eax, dwProcAddress;
				mov ebx, idt2e;

				mov[ebx], ax;
				shr eax, 16;
				mov[ebx + 6], ax;

				//call SetSmap;

				sti;
			}
			KdPrint(("Processor[%d] is hooked, dwProcAddress: 0x%08X\n", dwIndex + 1, dwProcAddress));
		}
	}

	KeSetAffinityThread(pkThread, cpuBitMap);
	PsTerminateSystemThread(STATUS_SUCCESS);
}
//-----------------------------------------------------------------------------//
void HookInt0E()
{
	HANDLE hThread;
	CLIENT_ID cid;
	PVOID pThread;

	KdPrint(("Start hooking...\n"));

	PsCreateSystemThread(&hThread, 0L, NULL, NULL, &cid, (PKSTART_ROUTINE)HookCPU, (PVOID)PageFaultHandler);
	if (hThread)
	{
		PsLookupThreadByThreadId(cid.UniqueThread, (PETHREAD *)&pThread);
		KeWaitForSingleObject(pThread, Executive, KernelMode, FALSE, NULL);
		ZwClose(hThread);
		KdPrint(("Hook is done.\n"));
	}
}
//-----------------------------------------------------------------------------//