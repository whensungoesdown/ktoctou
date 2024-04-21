#include <ntddk.h>
#include "structs.h"
#include "helper.h"
#include "cpu.h"
#include "vmx.h"
#include "i386/vmx-asm.h"
#include "i386/regs-asm.h"
#include "helper.h"
//-----------------------------------------------------------------------------//
ULONG g_Count = 0;

KSPIN_LOCK g_SpinkLock;
SMAP_PAGES g_SmapPages[MAX_SMAP_PAGE_NUM] = { 0 };

DWORD originalKiServiceExit = 0;

ULONG g_SmapExceptionCount = 0;
ULONG g_PrintMsg = 1;


ULONG g_VirtualAddress = 0;
//-----------------------------------------------------------------------------//
DWORD g_jumpback80541726 = 0x80541726;
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
BOOLEAN IsSmapPageExist (ULONG Cr3, ULONG Eip, ULONG Address, ULONG Teb, BOOLEAN Write)
{
	int i = 0;

	for (i = 0; i < MAX_SMAP_PAGE_NUM; i++)
	{
		if (TRUE == g_SmapPages[i].Used)
		{
			//g_SmapPages[i].Used = TRUE;
			//g_SmapPages[i].Cr3 = Cr3;
			//g_SmapPages[i].Eip = Eip;
			//g_SmapPages[i].Address = Address;
			//g_SmapPages[i].Teb = Teb;
			//g_Count++;

			//pPte = MiGetPteAddress(Address);

			//pPte->u.Hard.Owner = 0;
			////DbgPrint("add one page cr3 0x%x, address 0x%x\n", Cr3, Address);

			if (Address == g_SmapPages[i].Address && Eip != g_SmapPages[i].Eip && !Write)
			{
				DbgPrint("PREV SMAP CR3 0x%x, EIP 0x%x, Address 0x%x, TEB 0x%x\n", g_SmapPages[i].Cr3, g_SmapPages[i].Eip, g_SmapPages[i].Address, g_SmapPages[i].Teb);
				DbgPrint("     SMAP CR3 0x%x, EIP 0x%x, Address 0x%x, TEB 0x%x\n\n", Cr3, Eip, Address, Teb);

				return TRUE;
			}
		}
	}

	return FALSE;
}
//-----------------------------------------------------------------------------//
LONG AddSampPage(ULONG Cr3, ULONG Eip, ULONG Address, ULONG Teb, BOOLEAN Write)
{
	int i = 0;
	//PMMPTE pPte = NULL;
	KIRQL OldIrql;

	// uty: test only record read op
	if (Write) return STATUS_SUCCESS; 

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
LONG ReleaseSmapPages_Cr3_All (VOID)
{
	int i = 0;
	PMMPTE pPte = NULL;
	KIRQL OldIrql;
	int count = 0;
	BOOLEAN bReleasedTargetPage = FALSE;

	
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

		if (TRUE)
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
DWORD g_jumpback82a4c588 = 0x82a4c588;
//-----------------------------------------------------------------------------//
__declspec(naked) void FuncKiSystemCallExit2_win7()
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

        
		test dword ptr [esp+8],100h
		
		jmp g_jumpback82a4c588;
	}
}
//-----------------------------------------------------------------------------//
/*

nt!KiSystemCallExit2:
82a4c580 f744240800010000 test    dword ptr [esp+8],100h
82a4c588 75f5            jne     nt!KiSystemCallExit (82a4c57f)
82a4c58a 5a              pop     edx
82a4c58b 83c404          add     esp,4
82a4c58e 812424fffdffff  and     dword ptr [esp],0FFFFFDFFh
82a4c595 9d              popfd
82a4c596 59              pop     ecx
82a4c597 fb              sti


*/
int HookKiSystemCallExit2_win7()
{
	char hookcode[5] = { 0xe9, 0, 0, 0, 0 };

	// calc jmp offset 
	*((ULONG*)(hookcode + 1)) = (ULONG)FuncKiSystemCallExit2_win7 - 0x82a4c580 - 5;

	DisableWriteProtect();
	RtlCopyMemory((char*)0x82a4c580, hookcode, 5);
	EnableWriteProtect();
	return 0;
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
VOID ReleasePage (VOID)
{
	PMMPTE pPte = NULL;

	pPte = MiGetPteAddress(g_VirtualAddress);

	pPte->u.Hard.Write = 1; // uty: test
	pPte->u.Hard.Owner = 1;

	__invlpg(g_VirtualAddress);
}
//-----------------------------------------------------------------------------//
/*
 * user_mode(regs) determines whether a register set came from user
 * mode.  On x86_32, this is true if V8086 mode was enabled OR if the
 * register set was from protected mode with RPL-3 CS value.  This
 * tricky test checks that with one comparison.
 *
 * On x86_64, vm86 mode is mercifully nonexistent, and we don't need
 * the extra check.
 */
//static inline int user_mode(struct pt_regs *regs)
//{
//#ifdef CONFIG_X86_32
//	return ((regs->cs & SEGMENT_RPL_MASK) | (regs->flags & X86_VM_MASK)) >= USER_RPL;
//#else
//	return !!(regs->cs & 3);
//#endif
//}

__inline BOOLEAN user_mode(int cs)
{
	return (cs & SEGMENT_RPL_MASK) >= USER_RPL;
}
//-----------------------------------------------------------------------------//
BOOLEAN smap_violation(int error_codes, int cs, int flags)
{
	if (error_codes & PF_USER)
	{
		return FALSE;
	}

	//if ((FALSE == user_mode(cs)) && (flags & X86_EFLAGS_AC))
	if ((TRUE == user_mode(cs)) || (flags & X86_EFLAGS_AC))
	{
		return FALSE;
	}

	return TRUE;
}
//-----------------------------------------------------------------------------//
UCHAR g_OriByte = 0;
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


	//
	//  It's important to set interrupts right away, there may be nested page fault
	//  Also it seems to related to IPI
	//

	__asm sti;


	if ((ULONG)VirtualAddress >= (ULONG)0x80000000)
	{
		return 0;
	}

	if (0 == (error & PF_PROT))
	{
		return 0;
	}

	pPte = MiGetPteAddress(VirtualAddress);


	// For example, ProbeForWrite a user read-only memory
	if ((error & PF_WRITE) && (0 == pPte->u.Hard.Write) /*&& (1 == pPte->u.Hard.Owner)*/ && ((ULONG)VirtualAddress <= 0x80000000) /*&& !IsSmapPage(0, (ULONG)VirtualAddress)*/)
		                                                  // it's pte already been changed to KR, and it's a user address, 
	                                                      // for example: Smap violation :error code 0x3, cs 0x8, VA 0x12d1a8, cr3 0x6d401e0, eip 0x80615a85, eflags 0x10206, TEB 0x7ffdf000
		                                                  // 1: kd> u 0x80615a85 
		                                                  // nt!ProbeForWrite + 0x3b:
	{
		return 0;
	}


	if (smap_violation(error, ulCs, ulEflags) /*&& ((ULONG)ulEip > (ULONG)0x80000000)*/)
	{
		if (FALSE == IsSmapPageExist(ulCr3, ulEip, (ULONG)VirtualAddress, ulTeb, error & PF_WRITE))
		{
			AddSampPage(ulCr3, ulEip, (ULONG)VirtualAddress, ulTeb, error & PF_WRITE);
		}
		
		g_VirtualAddress = VirtualAddress;
		
		pPte = MiGetPteAddress(VirtualAddress);


		KeAcquireSpinLock(&g_SpinkLock, &OldIrql);
		pPte->u.Hard.Owner = 0;
		KeReleaseSpinLock(&g_SpinkLock, OldIrql);

		//DbgPrint("Smap violation :error code 0x%x, cs 0x%x, VA 0x%x, cr3 0x%x, eip 0x%x, eflags 0x%x, TEB 0x%x\n", error, ulCs, VirtualAddress, ulCr3, ulEip, ulEflags, ulTeb);

		{
			ULONG ulNextInst = 0;
			ULONG ulInstLen = 0;

			ulInstLen = GetOpCodeSize((PVOID)ulEip);
			ulNextInst = ulEip + ulInstLen;

			DisableWriteProtect();

			g_OriByte = *(PUCHAR)ulNextInst;

			if (g_OriByte == (UCHAR)0xcc)
			{
				__asm int 3;
			}
			*(PUCHAR)ulNextInst = (UCHAR)0xcc;

			EnableWriteProtect();

			//DbgPrint("Instruction Length: 0x%x, Original byte 0x%x\n", ulInstLen, g_OriByte);

		}	



		g_SmapExceptionCount++;

		return 1;
	}
	
	DbgPrint("Unhandled !!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");

	return 0;
}
//-----------------------------------------------------------------------------//