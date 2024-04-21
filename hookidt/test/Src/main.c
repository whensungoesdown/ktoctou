//  [5/6/2017 uty]
#include <ntddk.h>
#include "idt.h"
#include "smap.h"
#include "helper.h"
//-----------------------------------------------------------------------------//
__inline VOID NTAPI VmxVmCall1(ULONG32 num, ULONG32 arg0);

typedef ULONGLONG (*PKEFLUSHSINGLETB)(
	__in PVOID Virtual, 
	__in BOOLEAN Invalid,
	__in BOOLEAN AllProcessors,
	__in PULONGLONG PtePointer,
	__in ULONGLONG PteValue);
PKEFLUSHSINGLETB pKeFlushSingleTb = NULL;

typedef ULONGLONG(__stdcall *PKEFLUSHENTIRETB)(__in BOOLEAN AllProcessors, __in ULONG unused);
PKEFLUSHENTIRETB pKeFlushEntireTb = NULL;

typedef NTSTATUS(*PZWPROTECTVIRTUALMEMORY)(
	__in HANDLE ProcessHandle,
	__inout PVOID *BaseAddress,
	__inout PULONG NumberOfBytesToProtect,
	__in ULONG NewAccessProtection,
	__out PULONG OldAccessProtection);

PZWPROTECTVIRTUALMEMORY pZwProtectVirtualMemory = NULL;

typedef NTSTATUS(__stdcall *KeSetAffinityThreadPtr)(PKTHREAD thread, KAFFINITY affinity);
//-----------------------------------------------------------------------------//
//KSPIN_LOCK g_BitOpSpinLock;

ULONG g_Count = 0;

KSPIN_LOCK g_SpinkLock;
SMAP_PAGES g_SmapPages[MAX_SMAP_PAGE_NUM] = { 0 };

PIDT_DESCRIPTOR id0eAddr[MAX_NUMBER_OF_CPUS];
DWORD originalIDT2eISR;
DWORD originalKiServiceExit = 0;

ULONG g_SmapExceptionCount = 0;
ULONG g_PrintMsg = 1;

//-----------------------------------------------------------------------------//
#define PTE_BASE 0xc0000000

//++
// PMMPTE
// MiGetPteAddress (
//    IN PVOID va
//    );
//
// Routine Description:
//
//    MiGetPteAddress returns the address of the PTE which maps the
//    given virtual address.
//
// Arguments
//
//    Va - Supplies the virtual address to locate the PTE for.
//
// Return Value:
//
//    The address of the PTE.
//
//--

#define MiGetPteAddress(va) ((PMMPTE)(((((ULONG)(va)) >> 12) << 3) + PTE_BASE))  // PAE 8 bytes
//-----------------------------------------------------------------------------//
BOOLEAN IsAvailableSmap ()
{
	__asm
	{
		int 3
		mov eax, 07
		xor ecx, ecx
		cpuid                                   //; main-leaf = 07, sub-leaf = 0


		//;;
		//;; ¼ì²â CPUID.07H:EBX[20] Î»
		//;;
		and ebx, 0x100000                //; 1 << 20
		setnz al 
	}
}
//-----------------------------------------------------------------------------//
LONG AddSampPage(ULONG Cr3, ULONG Eip, ULONG Address, ULONG Teb)
{
	int i = 0;
	//PMMPTE pPte = NULL;
	KIRQL OldIrql;

	KeAcquireSpinLock(&g_SpinkLock, &OldIrql);

	if (g_Count >= MAX_SMAP_PAGE_NUM)
	{
		//DbgPrint("g_SmapPages is full!\n");
		goto Exit0;
	}

	for (i = 0; i < MAX_SMAP_PAGE_NUM; i++)
	{
		if (FALSE == g_SmapPages[i].Used)
		{
			g_SmapPages[i].Used = TRUE;
			g_SmapPages[i].Cr3 = Cr3;
			g_SmapPages[i].Eip = Eip;
			g_SmapPages[i].Address = Address;
			g_SmapPages[i].Teb = Teb;
			g_Count++;

			//pPte = MiGetPteAddress(Address);

			//pPte->u.Hard.Owner = 0;
			////DbgPrint("add one page cr3 0x%x, address 0x%x\n", Cr3, Address);

			goto Exit0;
		}
	}

	//DbgPrint("no free slot, g_Count %d\n", g_Count);

Exit0:
	KeReleaseSpinLock(&g_SpinkLock, OldIrql);
	return STATUS_SUCCESS;
}
//-----------------------------------------------------------------------------//
LONG ReleaseSmapPages_Cr3(ULONG Cr3, ULONG Teb)
{
	int i = 0;
	PMMPTE pPte = NULL;
	KIRQL OldIrql;
	int count = 0;
	BOOLEAN bReleasedTargetPage = FALSE;

	
	//if ((ULONG)0x34c000 == (ULONG)Cr3)
	if ((ULONG)0x2b40020 == (ULONG)Cr3)
	{
		return STATUS_SUCCESS;
	}

	KeAcquireSpinLock(&g_SpinkLock, &OldIrql);

	for (i = 0; i < MAX_SMAP_PAGE_NUM; i++)
	{
		if (g_Count <= 0)
		{
			break;
		}

		if (FALSE == g_SmapPages[i].Used)
		{
			continue;
		}

		if ((g_SmapPages[i].Cr3 == Cr3 && g_SmapPages[i].Teb == Teb) || g_SmapPages[i].Teb == 0) // some access just with teb == 0, get them out
		{
			//ULONG ulTeb = 0;
			//__asm
			//{
			//	mov eax, fs:0x18
			//	mov ulTeb, eax
			//}

			if ((g_SmapPages[i].Address & 0xFFFFF000) == 0x0)
			{
				bReleasedTargetPage = TRUE;
			}

			////DbgPrint("ReleaseSmapPages_Cr3: cr3 0x%x VirtualAddress 0x%x, TEB 0x%x\n", Cr3, g_SmapPages[i].Address, Teb);

			g_SmapPages[i].Used = FALSE;
			g_Count--;

			pPte = MiGetPteAddress(g_SmapPages[i].Address);

			pPte->u.Hard.Write = 1; // uty: test
			pPte->u.Hard.Owner = 1;
			__invlpg(g_SmapPages[i].Address);

			g_SmapPages[i].Cr3 = 0;
			g_SmapPages[i].Address = 0;
			count++;

			//KeReleaseSpinLock(&g_SpinkLock, OldIrql);

			

			//pPte = MiGetPteAddress(g_SmapPages[i].Address);

			//KeAcquireSpinLock(&g_BitOpSpinLock, &OldIrql);
			//pPte->u.Hard.Owner = 1;
			//pPte->u.Hard.Write = 1;
			//KeReleaseSpinLock(&g_BitOpSpinLock, OldIrql);

			//KeAcquireSpinLock(&g_SpinkLock, &OldIrql);
		}
	}

	////DbgPrint("ReleaseSmapPages_Cr3: process 0x%x release %d pages\n", Cr3, count);

	KeReleaseSpinLock(&g_SpinkLock, OldIrql);

	if (bReleasedTargetPage)
	{
		////DbgPrint("Released the 0x0 page\n");// , 0x4 data 0x%x, pte 0x%x\n", *(PULONG)0x4, *(PULONG)0xc0000000);
	}

	return STATUS_SUCCESS;
}
//-----------------------------------------------------------------------------//
LONG DumpSmapPages()
{
	int i = 0;

	//DbgPrint("DumpSmapPages\n");
	for (i = 0; i < MAX_SMAP_PAGE_NUM; i++)
	{
		if (TRUE == g_SmapPages[i].Used)
		{
			//DbgPrint("!!!!!! cr3 0x%x, eip 0x%x, Address 0x%x\n", g_SmapPages[i].Cr3, g_SmapPages[i].Eip, g_SmapPages[i].Address);
		}
	}
	//DbgPrint("---------\n");

	return STATUS_SUCCESS;
}
//-----------------------------------------------------------------------------//
BOOLEAN IsSmapPage(ULONG Cr3, ULONG VirtualAddress)
{
	int i = 0;

	for (i = 0; i < MAX_SMAP_PAGE_NUM; i++)
	{
		if (TRUE == g_SmapPages[i].Used && (((ULONG)VirtualAddress & 0xFFFFF000) == ((ULONG)g_SmapPages[i].Address & 0xFFFFF000)))
		{
			return TRUE;
		}
	}

	return FALSE;
}
//-----------------------------------------------------------------------------//
BOOLEAN IsMyselfHoldingAPage(ULONG Cr3, ULONG Teb, ULONG VirtualAddress)
{
	int i = 0;
	KIRQL OldIrql;
	PMMPTE pPte = NULL;

	for (i = 0; i < MAX_SMAP_PAGE_NUM; i++)
	{
		if (TRUE == g_SmapPages[i].Used && (((ULONG)VirtualAddress & 0xFFFFF000) == ((ULONG)g_SmapPages[i].Address & 0xFFFFF000)) && (Teb == g_SmapPages[i].Teb))
		{
			// uty: test, also remove this page
			KeAcquireSpinLock(&g_SpinkLock, &OldIrql);

			g_SmapPages[i].Used = FALSE;
			g_Count--;

			pPte = MiGetPteAddress(g_SmapPages[i].Address);

			if (0x4 == (ULONG)VirtualAddress) // uty: test
			{
				__asm int 3;
			}

			pPte->u.Hard.Owner = 1;
			pPte->u.Hard.Write = 1; // uty: test
			__invlpg(g_SmapPages[i].Address);
			//pKeFlushSingleTb(g_SmapPages[i].Address, FALSE);

			g_SmapPages[i].Cr3 = 0;
			g_SmapPages[i].Address = 0;

			KeReleaseSpinLock(&g_SpinkLock, OldIrql);

			return TRUE;
		}
	}

	return FALSE;
}
//-----------------------------------------------------------------------------//
void TestFlush()
{
	PVOID pBase = NULL;
	ULONG ulOldAccessProtection = 0;
	ULONG ulNumberOfBytesToProtect = 0;
	NTSTATUS Status = STATUS_SUCCESS;

	ulNumberOfBytesToProtect = 5;

	if (PASSIVE_LEVEL == KeGetCurrentIrql())
	{
		Status = pZwProtectVirtualMemory((HANDLE)-1, &pBase, &ulNumberOfBytesToProtect, PAGE_READWRITE, &ulOldAccessProtection);

		////DbgPrint("pZwProtectVirtualMemory return 0x%x\n", Status);
	}
	
}
//-----------------------------------------------------------------------------//
ULONG GetProcSetMember()
{
	ULONG ulSetMember = 0;
	ULONG ulKprcb = 0;

	__asm
	{
		mov eax, fs:0x20
		mov ecx, [eax + 0x14]
		mov ulSetMember, ecx
		mov ulKprcb, eax
	}

	//DbgPrint("current kprcb: 0x%x\n", ulKprcb);

	return ulSetMember;
}
//-----------------------------------------------------------------------------//
LONG HandleSmap(VOID)
{
	PVOID VirtualAddress = NULL;
	PMMPTE pPte = NULL;
	ULONG error = 0;
	ULONG ulEsp = 0;
	ULONG ulCr3 = 0;
	ULONG ulEip = 0;
	ULONG ulCs = 0;
	ULONG ulEflags = 0;
	ULONG ulTeb = 0;
	ULONG ulFs = 0;
	ULONG ulKprcb = 0;

	KIRQL OldIrql;

	

	__asm
	{
		mov eax, cr3
		mov ulCr3, eax
	}

	if (g_TargetCr3 != ulCr3)
	{
		return 0;
	}

	__asm
	{
		//int 3;
		mov eax, [ebp+0x30]
		mov error, eax

		mov eax, [ebp+0x34]
		mov ulEip, eax

		mov eax, [ebp+0x38]
		mov ulCs, eax

		mov eax, [ebp+0x3c]
		mov ulEflags, eax

		mov ulEsp, esp
		
		//mov eax, cr3
		//mov ulCr3, eax

		mov eax, fs:0x18
		mov ulTeb, eax

		xor eax, eax
		mov ax, fs
		mov ulFs, eax

		mov eax, fs:0x20
		mov ulKprcb, eax
	}


	VirtualAddress = (PVOID)__readcr2();

	if (g_PrintMsg)
	{
		//DbgPrint("error code 0x%x, cs 0x%x, VA 0x%x, cr3 0x%x, eip 0x%x eflags 0x%x\n", error, ulCs, VirtualAddress, ulCr3, ulEip, ulEflags);

		//if (ulEip == (ULONG)0x7c917402)
		//{
		//	__asm int 3;
		//}
	}

	//if (0x4 == (ULONG)VirtualAddress)
	//{
	//	//DbgPrint("Exception data 0x%x :error code 0x%x, cs 0x%x, VA 0x%x, cr3 0x%x, eip 0x%x, eflags 0x%x, Teb 0x%x\n", *(PULONG)0x4, error, ulCs, VirtualAddress, ulCr3, ulEip, ulEflags, ulTeb);

	//	//__asm int 3;
	//}
	//

	
	//if (error & PF_RSVD)
	//{
	//	////DbgPrint("PF_RSVD is 1, pass\n");
	//	return 0;
	//}


	//
	//  It's important to set interrupts right away, there may be nested page fault
	//  Also it seems to related to IPI
	//

	__asm sti;


	if ((ULONG)VirtualAddress >= (ULONG)0x80000000)
	{
		////DbgPrint("VirtualAddress bigger than 0x80000000, pass\n");
		return 0;
	}

	if (0 == (error & PF_PROT))
	{
		//if ((((ULONG)VirtualAddress & 0xFFFFF000) == 0x0) || (((ULONG)VirtualAddress & 0xFFFFF000) == 0xC0000000))
		//{
		//	//DbgPrint("???????????PF_PROT is 0, error code 0x%x, cs 0x%x, VA 0x%x, cr3 0x%x, eip 0x%x eflags 0x%x\n", error, ulCs, VirtualAddress, ulCr3, ulEip, ulEflags);
		//}
		////DbgPrint("PF_PROT is 0, error code 0x%x, cs 0x%x, VA 0x%x, cr3 0x%x, eip 0x%x eflags 0x%x\n", error, ulCs, VirtualAddress, ulCr3, ulEip, ulEflags);
		
		return 0;
	}

	//if (0 == (error & PF_PROT))
	//{

	//	if (0 == (error & PF_USER))
	//	{
	//		return 0;
	//	}
	//}


	pPte = MiGetPteAddress(VirtualAddress);


	// For example, ProbeForWrite a user read-only memory
	if ((error & PF_WRITE) && (0 == pPte->u.Hard.Write) /*&& (1 == pPte->u.Hard.Owner)*/ && ((ULONG)VirtualAddress <= 0x80000000) /*&& !IsSmapPage(0, (ULONG)VirtualAddress)*/)
		                                                  // it's pte already been changed to KR, and it's a user address, 
	                                                      // for example: Smap violation :error code 0x3, cs 0x8, VA 0x12d1a8, cr3 0x6d401e0, eip 0x80615a85, eflags 0x10206, TEB 0x7ffdf000
		                                                  // 1: kd> u 0x80615a85 
		                                                  // nt!ProbeForWrite + 0x3b:
	{
		//if (0x4 == (ULONG)VirtualAddress)
		//{
		//	//DbgPrint("?????????????????? 0x0 page, Write a user read-only page, error code 0x%x, cs 0x%x, VA 0x%x, cr3 0x%x, eip 0x%x eflags 0x%x\n", error, ulCs, VirtualAddress, ulCr3, ulEip, ulEflags);
		//}
		//
		return 0;
	}

	////DbgPrint("error code 0x%x, cs 0x%x, VA 0x%x, cr3 0x%x, eip 0x%x eflags 0x%x\n", error, ulCs, VirtualAddress, ulCr3, ulEip, ulEflags);


	if (smap_violation(error, ulCs, ulEflags) /*&& ((ULONG)ulEip > (ULONG)0x80000000)*/)
	{
		//ULONG ulTeb = 0;

		// uty: test
		//if ((ULONG)0 != ulCr3)
		//{
		//	// set eflags AC bit
		//	ulEflags = ulEflags & X86_EFLAGS_AC;
		//	__asm
		//	{
		//		mov eax, ulEflags
		//		mov[ebp + 0x3c], eax

		//		//__ASM_STAC
		//		_emit 0x0f
		//		_emit 0x01
		//		_emit 0xcb
		//	}

		//	return 1; //hanle this exception by ourself
		//}


		//if (g_PrintMsg)
		//{
		//	if (ulEip == 0x8053d850       // nt!KiSystemServiceCopyArguments:
		//		|| ulEip == 0x8053d80a    // nt!KiSystemServiceAccessTeb:
		//		|| ulEip == 0x8060d1e9    // nt!ProbeForWrite+0x39:
		//		)
		//	{
		//		 // nothing
		//	}
		//	else
		//	{
//DbgPrint("Smap violation :error code 0x%x, cs 0x%x, VA 0x%x, cr3 0x%x, eip 0x%x, eflags 0x%x, TEB 0x%x\n", error, ulCs, VirtualAddress, ulCr3, ulEip, ulEflags, ulTeb);
		//	}
		//	
		//}

		AddSampPage(ulCr3, ulEip, (ULONG)VirtualAddress, ulTeb);
		
		pPte = MiGetPteAddress(VirtualAddress);


		KeAcquireSpinLock(&g_SpinkLock, &OldIrql);
		pPte->u.Hard.Owner = 0;
		KeReleaseSpinLock(&g_SpinkLock, OldIrql);

		// uty: test
		//pKeFlushSingleTb(VirtualAddress, FALSE, FALSE, (PULONGLONG)pPte, *(PULONGLONG)pPte);



		//pKeFlushSingleTb(VirtualAddress, FALSE, FALSE, pPte, *(PULONGLONG)pPte);
		//__invlpg(VirtualAddress);
		//__asm int 3;
		//pKeFlushSingleTb(VirtualAddress, FALSE);
		//__asm int 3;
		////DbgPrint("cs: 0x%x, fs: 0x%x\n", ulCs, ulFs);
		//if (ulFs != 0x30)
		//{
		//	__asm int 3;
		//}
		//pKeFlushEntireTb(TRUE, 0);
		//TestFlush();
		//__invlpg(0);
		//VmxVmCall1(0x30, 0);

		//if (ulKprcb == 0xffdff120/*g_TargetKprcb*/ /*&& (ULONG)VirtualAddress == 0x8*/)
		//{
			//LARGE_INTEGER time = { 0 };
			////DbgPrint("SetMember 0x%x\n", GetProcSetMember());
			//__asm cli;
			//pKeFlushEntireTb(FALSE, 0);
			//pKeFlushSingleTb(VirtualAddress, FALSE, FALSE, pPte, *(PULONGLONG)pPte);
			//__asm sti;
			// uty: test
			//time.QuadPart = (LONGLONG)-300000; // waits for 30 milliseconds

			//KeDelayExecutionThread(UserMode, TRUE, &time);
		//}
		

		//pPte->u.Hard.Write = 1; // no need


		g_SmapExceptionCount++;

		return 1;
	}
	//else if ((0x5 == error) || (0x7 == error) || (0x15 == error))
	else if (((ULONG)ulEip < (ULONG)0x80000000) && (error & PF_USER) /*&& (pPte->u.Hard.Owner == 0)*/)
	{

		if (!IsSmapPage(0, (ULONG)VirtualAddress) && (0x4 != (ULONG)VirtualAddress))  // uty: bug  need cr3
		{
			pPte = MiGetPteAddress(VirtualAddress);

			//DbgPrint("Pass, Not SMAP page, 0x%x!!\n", VirtualAddress);

			/// uty: test
			//KeAcquireSpinLock(&g_SpinkLock, &OldIrql);
			//pPte->u.Hard.Owner = 1;
			//KeReleaseSpinLock(&g_SpinkLock, OldIrql);
			//__invlpg(VirtualAddress);

			
			return 1;
		}

		if (g_PrintMsg)
		{
//DbgPrint("!!!Access a smap page :error code 0x%x, cs 0x%x, VA 0x%x, cr3 0x%x, eip 0x%x eflags 0x%x, Teb 0x%x\n", error, ulCs, VirtualAddress, ulCr3, ulEip, ulEflags, ulTeb);
		}

		if ((ULONG)ulEip == 0x7c90e4f4   // ntdll!KiFastSystemCallRet
			|| (ULONG)ulEip == 0x7c90e434 // ntdll!KiUserApcDispatcher + 0x4
			|| (ULONG)ulEip == 0x7c81070b
			|| (ULONG)ulEip == 0x7c90e45c // ntdll!KiUserExceptionDispatcher
			|| (ULONG)ulEip == 0x7c90e8b0 // ntdll!_SEH_prolog+0x5

			//|| (ULONG)ulEip == 0x7e418603
			//|| (ULONG)ulEip == 0x7e419335
			//|| (ULONG)ulEip == 0x77f16a17
			//|| (ULONG)ulEip == 0x7c90fe40
			//|| (ULONG)ulEip == 0x77f159da
			//|| (ULONG)ulEip == 0x7e42a4d5
			//|| (ULONG)ulEip == 0x77f1613a
			//|| (ULONG)ulEip == 0x77f16b83
			//|| (ULONG)ulEip == 0x5ad76033
			//|| (ULONG)ulEip == 0x7c90e443
			//|| (ULONG)ulEip == 0x7c8106eb
			|| ((ULONG)VirtualAddress & 0xFFF00000) == 0x7ff00000
			)
		{
			pPte = MiGetPteAddress(VirtualAddress);

//DbgPrint("Pass!! VA: 0x%x\n", (ULONG)VirtualAddress);

			KeAcquireSpinLock(&g_SpinkLock, &OldIrql);
			pPte->u.Hard.Owner = 1;
			//pPte->u.Hard.Write = 1; // uty: test
			KeReleaseSpinLock(&g_SpinkLock, OldIrql);
			//__invlpg(VirtualAddress);
			//pKeFlushSingleTb(VirtualAddress, FALSE);

			
			return 1;
		}
		else
		{

			//pPte = MiGetPteAddress(VirtualAddress);

			//pPte->u.Hard.Owner = 1;
			//pPte->u.Hard.Write = 0;

			//error = error | PF_WRITE;

			//__asm
			//{
			//	mov error, eax
			//	mov [ebp + 0x30], eax
			//}

			////DbgPrint("Deny!! Change to READ_ONLY\n");

			////DumpSmapPages();
			//return 0;

			pPte = MiGetPteAddress(VirtualAddress);

			if (error & PF_WRITE)
			{
				LARGE_INTEGER time;
				int cnt = 10;

				if (IsMyselfHoldingAPage(0, ulTeb, (ULONG)VirtualAddress))  // the thread itself is holding this page.
				{
//DbgPrint("The thread itself is holding this page. Pass!! VA: 0x%x\n", (ULONG)VirtualAddress);

					KeAcquireSpinLock(&g_SpinkLock, &OldIrql);
					pPte->u.Hard.Owner = 1;
					//pPte->u.Hard.Write = 1; // uty: test
					KeReleaseSpinLock(&g_SpinkLock, OldIrql);
					//__invlpg(VirtualAddress);
					//pKeFlushSingleTb(VirtualAddress, FALSE);

					
					return 1;
				}



				while (TRUE)
				{
					// uty: test
					time.QuadPart = (LONGLONG)-300000; // waits for 30 milliseconds

					KeDelayExecutionThread(UserMode, TRUE, &time);

//DbgPrint("Wait 30 milliseconds, retry.. %d\n", cnt);

					if (1 == pPte->u.Hard.Write && 1 == pPte->u.Hard.Owner)
					{
//DbgPrint("OK, re-execute \n");
						break;
					}

					cnt--;

					if (cnt <= 0)
					{
						KeAcquireSpinLock(&g_SpinkLock, &OldIrql);
						//pPte->u.Hard.Owner = 1;
						//pPte->u.Hard.Write = 0;

						pPte->u.Hard.Valid = 0; // uty: test
						KeReleaseSpinLock(&g_SpinkLock, OldIrql);
						//__invlpg(VirtualAddress);
						//pKeFlushSingleTb(VirtualAddress, FALSE);
						error = error & ~PF_PROT;
						//DbgPrint("Deny!\n");
						return 0;
					}
				}
				
				return 1;
			}
			else
			{
//DbgPrint("Read Access from user!! Change to READ_ONLY\n");

				KeAcquireSpinLock(&g_SpinkLock, &OldIrql);
				pPte->u.Hard.Write = 0;
				pPte->u.Hard.Owner = 1;
				KeReleaseSpinLock(&g_SpinkLock, OldIrql);
				//__invlpg(VirtualAddress);
				//pKeFlushSingleTb(VirtualAddress, FALSE);
				
				return 1;
			}
		}
	}

	return 1;
}
//-----------------------------------------------------------------------------//
void RecoverPages()
{
	ULONG ulCr3 = 0;
	ULONG ulTeb = 0;

	__asm
	{
		mov eax, cr3
		mov ulCr3, eax

		mov eax, fs:0x18
		mov ulTeb, eax
	}

	ReleaseSmapPages_Cr3(ulCr3, ulTeb);
}
//-----------------------------------------------------------------------------//
void
DisableWriteProtect()
{
	__asm {
		cli
		mov   eax, cr0
		and   eax, 0FFFEFFFFh
		mov   cr0, eax
	}
}
//-----------------------------------------------------------------------------//
void EnableWriteProtect()
{
	__asm {
		mov   eax, cr0
		or eax, not 0FFFEFFFFh
		mov   cr0, eax
		sti
	}
}
//-----------------------------------------------------------------------------//
__declspec(naked) void KiServiceExitFunc()
{
	__asm
	{
		pushad
		pushfd
		push fs
		mov bx, 0x30
		mov fs, bx

		cli  // therefore, on signle cpu, no need for spinlock

		call RecoverPages


		pop fs
		popfd
		popad


		//cli
		test dword ptr[ebp + 70h], 20000h
		jmp originalKiServiceExit;
	}
}
//-----------------------------------------------------------------------------//
/*
nt!KiServiceExit:
8053d865 fa              cli
8053d866 f7457000000200  test    dword ptr [ebp+70h],20000h
8053d86d 7506            jne     nt!KiServiceExit+0x10 (8053d875)
8053d86f f6456c01        test    byte ptr [ebp+6Ch],1
8053d873 7457            je      nt!KiServiceExit+0x67 (8053d8cc)
8053d875 8b1d24f1dfff    mov     ebx,dword ptr ds:[0FFDFF124h]
8053d87b c6432e00        mov     byte ptr [ebx+2Eh],0
8053d87f 807b4a00        cmp     byte ptr [ebx+4Ah],0
*/
int HookKiServiceExit()
{
	// JMP xxxxxxxx 
	char g_cHookCode[5] = { 0xe9, 0, 0, 0, 0 };

	originalKiServiceExit = 0x8053d86d;

	// calc jmp offset 
	*((ULONG*)(g_cHookCode + 1)) = (ULONG)KiServiceExitFunc - 0x8053d865 - 5;

	DisableWriteProtect();
	RtlCopyMemory((char*)0x8053d865, g_cHookCode, 5);
	EnableWriteProtect();
	return 0;
}
//-----------------------------------------------------------------------------//
//DWORD g_jumpback8053d8d7 = 0x8053d8d7;
//-----------------------------------------------------------------------------//
//__declspec(naked) Func8053d8d0()
//{
//	__asm
//	{
//		pushad
//		pushfd
//		push fs
//		mov bx, 0x30
//		mov fs, bx
//
//
//		// already cli
//
//		call RecoverPages
//
//
//		pop fs
//		popfd
//		popad
//
//
//		mov ebx, dword ptr fs : [50h]
//		jmp g_jumpback8053d8d7;
//	}
//}

DWORD g_jumpback8054169f = 0x8054169f;

__declspec(naked) void Func80541699()
{
	__asm
	{
		pushad
		pushfd
		push fs
		mov bx, 0x30
		mov fs, bx


		// already cli

		call RecoverPages


		pop fs
		popfd
		popad


		mov ebx, dword ptr fs : [50h]
		jmp g_jumpback8054169f;
	}
}
//-----------------------------------------------------------------------------//
/*
kd> u 8053d8d0
nt!KiServiceExit + 0x6b:
8053d8d0 648b1d50000000  mov     ebx, dword ptr fs : [50h]
8053d8d7 64891500000000  mov     dword ptr fs : [0], edx
8053d8de 8b4c2448        mov     ecx, dword ptr[esp + 48h]
8053d8e2 648b3524010000  mov     esi, dword ptr fs : [124h]
8053d8e9 888e40010000    mov     byte ptr[esi + 140h], cl
8053d8ef f7c3ff000000    test    ebx, 0FFh
8053d8f5 7579            jne     nt!KiSystemCallExit2 + 0x17 (8053d970)
8053d8f7 f744247000000200 test    dword ptr[esp + 70h], 20000h
*/

//int HookKiServiceExit8053d8d0 ()
//{
//	char hookcode[5] = { 0xe9, 0, 0, 0, 0 };
//	// calc jmp offset 
//	*((ULONG*)(hookcode + 1)) = (ULONG)Func8053d8d0 - 0x8053d8d0 - 5;
//
//	DisableWriteProtect();
//	RtlCopyMemory((char*)0x8053d8d0, hookcode, 5);
//	EnableWriteProtect();
//	return 0;
//}

/*
kd> u nt!KiServiceExit+0x6b
nt!KiServiceExit+0x6b:
80541699 8b1d50000000    mov     ebx,dword ptr ds:[50h]
8054169f 64891500000000  mov     dword ptr fs:[0],edx
805416a6 8b4c2448        mov     ecx,dword ptr [esp+48h]
805416aa 648b3524010000  mov     esi,dword ptr fs:[124h]
805416b1 888e40010000    mov     byte ptr [esi+140h],cl
805416b7 f7c3ff000000    test    ebx,0FFh
805416bd 7579            jne     nt!KiSystemCallExit2+0x17 (80541738)
805416bf f744247000000200 test    dword ptr [esp+70h],20000h

*/

int HookKiServiceExit80541699()
{
	char hookcode[5] = { 0xe9, 0, 0, 0, 0 };
	// calc jmp offset 
	*((ULONG*)(hookcode + 1)) = (ULONG)Func80541699 - 0x80541699 - 5;

	DisableWriteProtect();
	RtlCopyMemory((char*)0x80541699, hookcode, 5);
	EnableWriteProtect();
	return 0;
}
//-----------------------------------------------------------------------------//
DWORD g_jumpback8053da53 = 0x8053da53;
//-----------------------------------------------------------------------------//
__declspec(naked) void Func8053da4c()
{
	__asm
	{
		pushad
		pushfd
		push fs
		mov bx, 0x30
		mov fs, bx


		// already cli

		call RecoverPages


		pop fs
		popfd
		popad


		mov ebx, dword ptr fs : [50h]
		jmp g_jumpback8053da53;
	}
}
//-----------------------------------------------------------------------------//
/*
kd> u 8053da4c
nt!KiServiceExit2+0x4a:
8053da4c 648b1d50000000  mov     ebx,dword ptr fs:[50h]
8053da53 64891500000000  mov     dword ptr fs:[0],edx
8053da5a 8b4c2448        mov     ecx,dword ptr [esp+48h]
8053da5e 648b3524010000  mov     esi,dword ptr fs:[124h]
8053da65 888e40010000    mov     byte ptr [esi+140h],cl
8053da6b f7c3ff000000    test    ebx,0FFh
8053da71 7551            jne     nt!KiServiceExit2+0xc2 (8053dac4)
8053da73 f744247000000200 test    dword ptr [esp+70h],20000h
*/
int HookKiServiceExit28053da4c()
{
	char hookcode[5] = { 0xe9, 0, 0, 0, 0 };

	// calc jmp offset 
	*((ULONG*)(hookcode + 1)) = (ULONG)Func8053da4c - 0x8053da4c - 5;

	DisableWriteProtect();
	RtlCopyMemory((char*)0x8053da4c, hookcode, 5);
	EnableWriteProtect();
	return 0;
}
//-----------------------------------------------------------------------------//
DWORD g_jumpback80541726 = 0x80541726;
//-----------------------------------------------------------------------------//
__declspec(naked) void FuncKiSystemCallExit2()
{
	__asm
	{
		pushad
		pushfd
		push fs
		mov bx, 0x30
		mov fs, bx


		//cli  //test

		call RecoverPages


		pop fs
		popfd
		popad


		test byte ptr[esp + 9], 1
		jmp g_jumpback80541726;
	}
}
//-----------------------------------------------------------------------------//
/*
1: kd> u nt!KiSystemCallExit2
nt!KiSystemCallExit2:
80541721 f644240901      test    byte ptr [esp+9],1
80541726 75f8            jne     nt!KiSystemCallExit (80541720)
80541728 5a              pop     edx
80541729 83c404          add     esp,4
8054172c 80642401fd      and     byte ptr [esp+1],0FDh
80541731 9d              popfd
80541732 59              pop     ecx
80541733 fb              sti

*/
int HookKiSystemCallExit2()
{
	char hookcode[5] = { 0xe9, 0, 0, 0, 0 };

	// calc jmp offset 
	*((ULONG*)(hookcode + 1)) = (ULONG)FuncKiSystemCallExit2 - 0x80541721 - 5;

	DisableWriteProtect();
	RtlCopyMemory((char*)0x80541721, hookcode, 5);
	EnableWriteProtect();
	return 0;
}
//-----------------------------------------------------------------------------//
__declspec(naked) void KiSystemServiceHook()
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

DWORD makeDWORD(WORD hi, WORD lo)
{
	DWORD value = 0;
	value = value | (DWORD)hi;
	value <<= 16;
	value = value | (DWORD)lo;
	return value;
}

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

void HookInt0E(DWORD dwProcAddress)
{
	HANDLE hThread;
	CLIENT_ID cid;
	PVOID pThread;

	KdPrint(("Start hooking...\n"));

	PsCreateSystemThread(&hThread, 0L, NULL, NULL, &cid, (PKSTART_ROUTINE)HookCPU, (PVOID)dwProcAddress);
	if (hThread)
	{
		PsLookupThreadByThreadId(cid.UniqueThread, (PETHREAD *)&pThread);
		KeWaitForSingleObject(pThread, Executive, KernelMode, FALSE, NULL);
		ZwClose(hThread);
		KdPrint(("Hook is done.\n"));
	}
}
//-----------------------------------------------------------------------------//
//VOID SetSmap ()
//{
//	int cr4 = 0;
//	//__asm
//	//{
//	//	mov eax, cr4
//	//	or eax, 0x200000;   // 21 bit
//	//	mov cr4, eax
//	//}
//
//	cr4 = __readcr4();
//
//	cr4 |= 0x200000;
//
//	__writecr4(cr4);
//}
//-----------------------------------------------------------------------------//
NTSTATUS
DriverEntry (
	__in PDRIVER_OBJECT DriverObject,
	__in PUNICODE_STRING RegistryPath
	)
{
	//__asm int 3;
	KeInitializeSpinLock(&g_SpinkLock);

	//KeInitializeSpinLock(&g_BitOpSpinLock);
	//IsAvailableSmap();

	HookInt0E((DWORD)KiSystemServiceHook); 


	//HookKiServiceExit();
	////DbgPrint("HookKiServiceExit\n");

	//HookKiServiceExit8053d8d0(); // after KiDeliverApc, cli
	//HookKiServiceExit80541699(); // uty: test
	////DbgPrint("HookKiServiceExit80541699 \n"); 

	//HookKiServiceExit28053da4c();
	////DbgPrint("HookKiServiceExit28053da4c \n");

	HookKiSystemCallExit2();
	//DbgPrint("HookKiSystemCallExit2\n");

	//
	// temp
	//

	//SetSmap();

	//KdPrint(("SetSmap is done.\n"));

	
	FindTargetProcess();

	pKeFlushSingleTb = (PKEFLUSHSINGLETB)0x804fb482;

	pKeFlushEntireTb = (PKEFLUSHENTIRETB)0x804fb2b4;

	pZwProtectVirtualMemory = (PZWPROTECTVIRTUALMEMORY)0x805007e0;

	return STATUS_SUCCESS;
}
//-----------------------------------------------------------------------------//