//  [5/6/2017 uty]
#include <ntddk.h>
#include "idt.h"
#include "smap.h"
//-----------------------------------------------------------------------------//

//
// A Page Table Entry on the x86 has the following definition.
// Note the MP version is to avoid stalls when flushing TBs across processors.
//

typedef struct _MMPTE_HARDWARE {
	ULONG Valid : 1;
#if defined(NT_UP)
	ULONG Write : 1;       // UP version
#else
	ULONG Writable : 1;    // changed for MP version
#endif
	ULONG Owner : 1;
	ULONG WriteThrough : 1;
	ULONG CacheDisable : 1;
	ULONG Accessed : 1;
	ULONG Dirty : 1;
	ULONG LargePage : 1;
	ULONG Global : 1;
	ULONG CopyOnWrite : 1; // software field
	ULONG Prototype : 1;   // software field
#if defined(NT_UP)
	ULONG reserved : 1;    // software field
#else
	ULONG Write : 1;       // software field - MP change
#endif
	ULONG PageFrameNumber : 20;
} MMPTE_HARDWARE, *PMMPTE_HARDWARE;


typedef struct _MMPTE {
	union {
		ULONG Long;
		MMPTE_HARDWARE Hard;
	} u;
} MMPTE;

typedef MMPTE *PMMPTE;

VOID SetSmap();
//-----------------------------------------------------------------------------//
typedef struct _SMAP_PAGES
{
	BOOLEAN Used;
	ULONG Cr3;
	ULONG Eip;
	ULONG Address;
	ULONG Teb;
} SMAP_PAGES, *PSMAP_PAGES;

#define MAX_SMAP_PAGE_NUM	1024

ULONG g_Count = 0;

KSPIN_LOCK g_SpinkLock;
SMAP_PAGES g_SmapPages[MAX_SMAP_PAGE_NUM] = { 0 };
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
typedef	USHORT	WORD;
typedef	ULONG	DWORD;

typedef NTSTATUS(__stdcall *KeSetAffinityThreadPtr)(PKTHREAD thread, KAFFINITY affinity);

#define SYSTEM_SERVICE_VECTOR 0x0e
#define MAX_NUMBER_OF_CPUS sizeof(KAFFINITY)

// nonstandard extension used : bit field types other than int
#pragma warning(disable: 4214)
// unreferenced formal parameter
#pragma warning(disable: 4100)
#pragma warning(disable: 4055)

#pragma pack(1)
typedef struct _IDT_DESCRIPTOR
{
	//--------------------------
	WORD offset00_15;	//Bits[00,15] offset address bits [8,15]
	WORD selector;		//Bits[16,31] segment selector (value placed in CS)
						//--------------------------
	CHAR unused : 5;		//Bits[00,94] not used
	CHAR zeroes : 3;		//Bits[85,87] these three bits should all be zero
	CHAR gateType : 5;	//Bits[B8,12] Interrupt (81118),  Trap (81111)
	CHAR DPL : 2;			//Bits[13,14] DPL - descriptor privilege level
	CHAR P : 1;			//Bits[15,15] Segment present flag (normally set)
	WORD offset16_31;	//Bits[16,32] offset address bits [16,31]
}IDT_DESCRIPTOR, *PIDT_DESCRIPTOR;
#pragma pack()

//#pragma pack(1)
//typedef struct _IDTR
//{
//	WORD nBytes;		//Bits[00,15] size limit (in bytes)
//	WORD baseAddressLo;	//Bits[16,31] lo-order bytes of base address
//	WORD baseAddressHi;	//Bits[32,47] hi-order bytes of base address
//}IDTR;
//#pragma pack()
//-----------------------------------------------------------------------------//
PIDT_DESCRIPTOR idt2eAddr[MAX_NUMBER_OF_CPUS];
DWORD originalIDT2eISR;
DWORD originalKiServiceExit = 0;

void logSystemCall(DWORD dispatchID, DWORD stackPtr)
{
	KdPrint(("[RegisterSystemCall]: on CPU[%u] of %u, (%s, pid=%u, dispatchID=0x%x)\n",
		KeGetCurrentProcessorNumber() + 1, KeNumberProcessors, (CHAR *)PsGetCurrentProcess() + 0x16C, PsGetCurrentProcessId(), dispatchID));
}

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

#define MiGetPteAddress(va) ((PMMPTE)(((((ULONG)(va)) >> 12) << 3) + PTE_BASE))

LONG AddSampPage(ULONG Cr3, ULONG Eip, ULONG Address, ULONG Teb)
{
	int i = 0;
	//PMMPTE pPte = NULL;
	//KIRQL OldIrql;

	//KeAcquireSpinLock(&g_SpinkLock, &OldIrql);

	if (g_Count >= MAX_SMAP_PAGE_NUM)
	{
		DbgPrint("g_SmapPages is full!\n");
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
			//DbgPrint("add one page cr3 0x%x, address 0x%x\n", Cr3, Address);

			goto Exit0;
		}
	}

	DbgPrint("no free slot, g_Count %d\n", g_Count);

Exit0:
	//KeReleaseSpinLock(&g_SpinkLock, OldIrql);
	return STATUS_SUCCESS;
}
//-----------------------------------------------------------------------------//
LONG ReleaseSmapPages_Cr3(ULONG Cr3, ULONG Teb)
{
	int i = 0;
	PMMPTE pPte = NULL;
	//KIRQL OldIrql;
	int count = 0;

	
	//if ((ULONG)0x34c000 == (ULONG)Cr3)
	if ((ULONG)0x2b40020 == (ULONG)Cr3)
	{
		return STATUS_SUCCESS;
	}

	//KeAcquireSpinLock(&g_SpinkLock, &OldIrql);

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

		if (g_SmapPages[i].Cr3 == Cr3 && g_SmapPages[i].Teb == Teb)
		{
			//ULONG ulTeb = 0;
			//__asm
			//{
			//	mov eax, fs:0x18
			//	mov ulTeb, eax
			//}

			//DbgPrint("ReleaseSmapPages_Cr3: cr3 0x%x VirtualAddress 0x%x, TEB 0x%x\n", Cr3, g_SmapPages[i].Address, Teb);

			g_SmapPages[i].Used = FALSE;
			g_Count--;

			pPte = MiGetPteAddress(g_SmapPages[i].Address);

			pPte->u.Hard.Owner = 1;
			pPte->u.Hard.Write = 1;

			g_SmapPages[i].Cr3 = 0;
			g_SmapPages[i].Address = 0;
			count++;

			
		}
	}

	//DbgPrint("ReleaseSmapPages_Cr3: process 0x%x release %d pages\n", Cr3, count);

	//KeReleaseSpinLock(&g_SpinkLock, OldIrql);

	return STATUS_SUCCESS;
}
//-----------------------------------------------------------------------------//
LONG DumpSmapPages()
{
	int i = 0;

	DbgPrint("DumpSmapPages\n");
	for (i = 0; i < MAX_SMAP_PAGE_NUM; i++)
	{
		if (TRUE == g_SmapPages[i].Used)
		{
			DbgPrint("!!!!!! cr3 0x%x, eip 0x%x, Address 0x%x\n", g_SmapPages[i].Cr3, g_SmapPages[i].Eip, g_SmapPages[i].Address);
		}
	}
	DbgPrint("---------\n");

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
ULONG g_PrintMsg = 1;

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
		
		mov eax, cr3
		mov ulCr3, eax

	}

	

	VirtualAddress = __readcr2();

	//if (g_PrintMsg)
	//{
	//	DbgPrint("error code 0x%x, cs 0x%x, VA 0x%x, cr3 0x%x, eip 0x%x eflags 0x%x\n", error, ulCs, VirtualAddress, ulCr3, ulEip, ulEflags);
	//	if (ulEip == (ULONG)0x7c917402)
	//	{
	//		__asm int 3;
	//	}
	//}
	

	
	//if (error & PF_RSVD)
	//{
	//	//DbgPrint("PF_RSVD is 1, pass\n");
	//	return 0;
	//}


	if ((ULONG)VirtualAddress >= (ULONG)0x80000000)
	{
		//DbgPrint("VirtualAddress bigger than 0x80000000, pass\n");
		return 0;
	}

	if (0 == (error & PF_PROT))
	{
		//DbgPrint("PF_PROT is 0, pass\n");
		//DbgPrint("PF_PROT is 0, error code 0x%x, cs 0x%x, VA 0x%x, cr3 0x%x, eip 0x%x eflags 0x%x\n", error, ulCs, VirtualAddress, ulCr3, ulEip, ulEflags);
		return 0;
	}
	//if (0 == (error & PF_PROT))
	//{

	//	if (0 == (error & PF_USER))
	//	{
	//		return 0;
	//	}
	//}

	//DbgPrint("error code 0x%x, cs 0x%x, VA 0x%x, cr3 0x%x, eip 0x%x eflags 0x%x\n", error, ulCs, VirtualAddress, ulCr3, ulEip, ulEflags);

	//pPte = MiGetPteAddress(ulEip);
	//if ((pPte->u.Hard.Owner == 0) && (error & PF_USER))
	//{
	//	//DbgPrint("!!!!!!!!!!!!! eip < 0x80000000, pPte->u.Hard.Owner == 0, error code 0x%x, cs 0x%x, VA 0x%x, cr3 0x%x, eip 0x%x eflags 0x%x\n", error, ulCs, VirtualAddress, ulCr3, ulEip, ulEflags);
	//	pPte->u.Hard.Owner == 1;
	//	return 1;
	//}

	pPte = MiGetPteAddress(VirtualAddress);


	if (smap_violation(error, ulCs, ulEflags) /*&& ((ULONG)ulEip > (ULONG)0x80000000)*/)
	//if ((0x1 == error) || (0x3 == error))
	{
		ULONG ulTeb = 0;

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

		if (g_PrintMsg)
		{
			
			__asm
			{
				mov eax, fs:0x18
				mov ulTeb, eax
			}

			if (ulEip == 0x8053d850       // nt!KiSystemServiceCopyArguments:
				|| ulEip == 0x8053d80a    // nt!KiSystemServiceAccessTeb:
				|| ulEip == 0x8060d1e9    // nt!ProbeForWrite+0x39:
				)
			{
				 // nothing
			}
			else
			{
				// win the race!! DbgPrint("Smap violation :error code 0x%x, cs 0x%x, VA 0x%x, cr3 0x%x, eip 0x%x, eflags 0x%x, TEB 0x%x\n", error, ulCs, VirtualAddress, ulCr3, ulEip, ulEflags, ulTeb);
			}
			
		}
		
		pPte = MiGetPteAddress(VirtualAddress);

		pPte->u.Hard.Owner = 0;

		pPte->u.Hard.Write = 1; //
		//__asm int 3;

		AddSampPage(ulCr3, ulEip, VirtualAddress, ulTeb);

		return 1;
	}
	//else if ((0x5 == error) || (0x7 == error) || (0x15 == error))
	else if (((ULONG)ulEip < 0x80000000) && (error & PF_USER) && (pPte->u.Hard.Owner == 0))
	{

		if (!IsSmapPage(0, (ULONG)VirtualAddress))  // uty: bug  need cr3
		{
			pPte = MiGetPteAddress(VirtualAddress);

			pPte->u.Hard.Owner = 1;
			DbgPrint("Pass, Not SMAP page, 0x%x!!\n", VirtualAddress);
			return 1;
		}

		if (g_PrintMsg)
		{
			//DbgPrint("!!!Access a smap page :error code 0x%x, cs 0x%x, VA 0x%x, cr3 0x%x, eip 0x%x eflags 0x%x\n", error, ulCs, VirtualAddress, ulCr3, ulEip, ulEflags);
		}

		if ((ULONG)ulEip == 0x7c90e4f4   // ntdll!KiFastSystemCallRet
			|| (ULONG)ulEip == 0x7c90e434 // ntdll!KiUserApcDispatcher + 0x4
			|| (ULONG)ulEip == 0x7c81070b
			|| (ULONG)ulEip == 0x7c90e45c // ntdll!KiUserExceptionDispatcher
			|| (ULONG)ulEip == 0x7c90e8b0 // ntdll!_SEH_prolog+0x5

			|| (ULONG)ulEip == 0x7e418603
			|| (ULONG)ulEip == 0x7e419335
			|| (ULONG)ulEip == 0x77f16a17
			|| (ULONG)ulEip == 0x7c90fe40
			|| (ULONG)ulEip == 0x77f159da
			|| (ULONG)ulEip == 0x7e42a4d5
			|| (ULONG)ulEip == 0x77f1613a
			|| (ULONG)ulEip == 0x77f16b83
			|| (ULONG)ulEip == 0x5ad76033
			|| (ULONG)ulEip == 0x7c90e443
			|| (ULONG)ulEip == 0x7c8106eb 
			|| ((ULONG)VirtualAddress & 0xFFFF0000) == 0x7ffd0000
			)
		{
			pPte = MiGetPteAddress(VirtualAddress);

			pPte->u.Hard.Owner = 1;

			//DbgPrint("Pass!!\n");
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

			//DbgPrint("Deny!! Change to READ_ONLY\n");

			////DumpSmapPages();
			//return 0;

			pPte = MiGetPteAddress(VirtualAddress);

			if (error & PF_WRITE)
			{
				pPte->u.Hard.Owner = 1;
				pPte->u.Hard.Write = 0;

				//error = error | PF_WRITE;

				//__asm
				//{
				//	mov eax, error
				//	mov [ebp + 0x30], eax
				//}

				//DbgPrint("Write Access! Deny! Change to READ_ONLY\n"); // process switch could happen during DbgPrint
				// when wrting multiple times, with DbgPrint, system may crash, still looking for reason 
				_mm_clflush(VirtualAddress);
				__invlpg(VirtualAddress);

				//__asm int 3;

				return 0;
			}
			else
			{
				pPte->u.Hard.Owner = 1;
				pPte->u.Hard.Write = 0;

				DbgPrint("Read Access from user!! Change to READ_ONLY\n");
				return 1;
			}


		}
		


		
	}

	//if ((ulEip == (ULONG)0x7e42968c))
	//{
	//	DbgPrint("!!!!!!!!!!!!!!!!!!error code 0x%x, cs 0x%x, VA 0x%x, cr3 0x%x, eip 0x%x eflags 0x%x\n", error, ulCs, VirtualAddress, ulCr3, ulEip, ulEflags);
	//}
	
	//__asm 
	//{
	//	mov eax, cr2
	//	mov VirtualAddress, eax
	//}

	return 0;
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
__declspec(naked) KiServiceExitFunc()
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

__declspec(naked) Func80541699()
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
__declspec(naked) Func8053da4c()
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
DWORD g_jumpback8053d95e = 0x8053d95e;
//-----------------------------------------------------------------------------//
__declspec(naked) FuncKiSystemCallExit2()
{
	__asm
	{
		pushad
		pushfd
		push fs
		mov bx, 0x30
		mov fs, bx


		cli  //test

		call RecoverPages


		pop fs
		popfd
		popad


		test byte ptr[esp + 9], 1
		jmp g_jumpback8053d95e;
	}
}
//-----------------------------------------------------------------------------//
/*
nt!KiSystemCallExit2:
8053d959 f644240901      test    byte ptr [esp+9],1
8053d95e 75f8            jne     nt!KiSystemCallExit (8053d958)
8053d960 5a              pop     edx
8053d961 83c404          add     esp,4
8053d964 80642401fd      and     byte ptr [esp+1],0FDh
8053d969 9d              popfd
8053d96a 59              pop     ecx
8053d96b fb              sti
*/
int HookKiSystemCallExit2()
{
	char hookcode[5] = { 0xe9, 0, 0, 0, 0 };

	// calc jmp offset 
	*((ULONG*)(hookcode + 1)) = (ULONG)FuncKiSystemCallExit2 - 0x8053d959 - 5;

	DisableWriteProtect();
	RtlCopyMemory((char*)0x8053d959, hookcode, 5);
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

			if (idt2eAddr[dwIndex] == 0)
			{
				__asm sidt idtr
				idt = (PIDT_DESCRIPTOR)makeDWORD(idtr.BaseHi, idtr.BaseLo);
				idt2eAddr[dwIndex] = idt + SYSTEM_SERVICE_VECTOR;
				if (originalIDT2eISR == 0)
					originalIDT2eISR = makeDWORD(idt2eAddr[dwIndex]->offset16_31, idt2eAddr[dwIndex]->offset00_15);
				KdPrint(("IDT: 0x%08X, originalIDT2eISR: 0x%08X\n", (DWORD)idt, originalIDT2eISR));
			}
			idt2e = (DWORD)idt2eAddr[dwIndex];

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

void HookInt2E(DWORD dwProcAddress)
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
	//KeInitializeSpinLock(&g_SpinkLock);
	//IsAvailableSmap();

	HookInt2E((DWORD)KiSystemServiceHook);


	//HookKiServiceExit();
	//DbgPrint("HookKiServiceExit\n");

	//HookKiServiceExit8053d8d0(); // after KiDeliverApc, cli
	HookKiServiceExit80541699();
	DbgPrint("HookKiServiceExit80541699 \n");

	//HookKiServiceExit28053da4c();
	//DbgPrint("HookKiServiceExit28053da4c \n");

	//HookKiSystemCallExit2();
	//DbgPrint("HookKiSystemCallExit2\n");

	//
	// temp
	//

	//SetSmap();

	//KdPrint(("SetSmap is done.\n"));

	

	

	return STATUS_SUCCESS;
}
//-----------------------------------------------------------------------------//