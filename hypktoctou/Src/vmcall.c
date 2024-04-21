//  [5/15/2015 uty]
#include <ntddk.h>
#include "ept.h"
#include "vmxexithandler.h"
#include "common.h"
//-----------------------------------------------------------------------------//
//typedef NTSTATUS (*PZWPROTECTVIRTUALMEMORY)(
//	__in HANDLE ProcessHandle,
//	__inout PVOID *BaseAddress,
//	__inout PULONG NumberOfBytesToProtect,
//	__in ULONG NewAccessProtection,
//	__out PULONG OldAccessProtection);
//
//PZWPROTECTVIRTUALMEMORY pZwProtectVirtualMemory = NULL;
//
//typedef ULONGLONG(__stdcall *PKEFLUSHENTIRETB)(__in BOOLEAN AllProcessors, __in ULONG unused);
//
//PKEFLUSHENTIRETB pKeFlushEntireTb = NULL;
//
//typedef ULONGLONG (*PKEFLUSHSINGLETB)(
//	__in PVOID Virtual, 
//	__in BOOLEAN Invalid,
//	__in BOOLEAN AllProcessors,
//	__in PULONGLONG PtePointer,
//	__in ULONGLONG PteValue);
//
//PKEFLUSHSINGLETB pKeFlushSingleTb = NULL;
////-----------------------------------------------------------------------------//
//void TestFlush()
//{
//	PVOID pBase = NULL;
//	ULONG ulOldAccessProtection = 0;
//	ULONG ulNumberOfBytesToProtect = 0;
//	NTSTATUS Status = STATUS_SUCCESS;
//
//	ulNumberOfBytesToProtect = 5;
//
//	__asm int 3;
//
//	if (NULL == pZwProtectVirtualMemory)
//	{
//		pZwProtectVirtualMemory = (PZWPROTECTVIRTUALMEMORY)0x805007e0;
//	}
//
//	if (PASSIVE_LEVEL == KeGetCurrentIrql())
//	{
//		Status = pZwProtectVirtualMemory((HANDLE)-1, &pBase, &ulNumberOfBytesToProtect, PAGE_READWRITE, &ulOldAccessProtection);
//
//		DbgPrint("pZwProtectVirtualMemory return 0x%x\n", Status);
//	}
//
//	//if (NULL == pKeFlushEntireTb)
//	//{
//	//	pKeFlushEntireTb = (PKEFLUSHENTIRETB)0x804fb2b4;
//	//}
//	//
//	//pKeFlushEntireTb(TRUE, 0);
//
//	//if (NULL == pKeFlushSingleTb)
//	//{
//	//	pKeFlushSingleTb = (PKEFLUSHSINGLETB)0x804fb482;
//	//}
//}
//-----------------------------------------------------------------------------//
VOID
HandleVMCALL (
	__inout PGUEST_REGS GuestRegs
	)
{
	//PVMM_INIT_STATE pCurrentVMMInitState = NULL;
	//pCurrentVMMInitState = &g_VMMInitState[KeGetCurrentProcessorNumber()];

	//if (0x25 == GuestRegs->eax)
	//{
	//	DbgPrint("in HandleVMCALL 0x25\n");
	//	SwitchToEPTOriginal(pCurrentVMMInitState);
	//}
	//else if (0x26 == GuestRegs->eax)
	//{
	//	DbgPrint("in HandleVMCALL 0x26\n");
	//	SwitchToEPTShadow(pCurrentVMMInitState);
	//}
	//else if (0x27 == GuestRegs->eax)
	//{
	//	PVOID pNewPage = NULL;
	//	PHYSICAL_ADDRESS PhysicalNewPage = {0};

	//	DbgPrint("in HandleVMCALL 0x27, arg0 0x%x\n", GuestRegs->ebx);
	//	pNewPage = MmAllocateNonCachedMemory(4096);
	//	if (NULL == pNewPage)
	//	{
	//		return;
	//	}
	//	PhysicalNewPage = MmGetPhysicalAddress(pNewPage);
	//	DbgPrint("New Physical Page 0x%x\n", PhysicalNewPage);
	//	DbgPrint("Map Guest Physical Page 0x%x to Host Physical Page 0x%x\n", GuestRegs->ebx, PhysicalNewPage.QuadPart);

	//	EptMapPage(&g_ept_shadow, FALSE, GuestRegs->ebx, PhysicalNewPage.QuadPart, EPTE_READ | EPTE_WRITE | EPTE_EXECUTE, CACHE_TYPE_WB, FALSE, &g_ShadowEptSpinLock);
	//}
	//else if (0x28 == GuestRegs->eax)
	//{
	//	DbgPrint("VMCALL 0x28, RBX 0x%x, RCX 0x%x\n", GuestRegs->ebx, GuestRegs->ecx);
	//	//
	//	// EBX is Guest Physical Page, ECX is the Host Physical Page should mapping with EBX
	//	//
	//	g_TmpShadowHookAddress = GuestRegs->ebx;
	//	DbgPrint("g_TmpShadowHookAddress 0x%x\n", g_TmpShadowHookAddress);

	//	EptSetPageAccess(&g_ept, FALSE, GuestRegs->ebx & 0xFFFFFFFFFFFFF000, EPTE_EXECUTE, &g_EptSpinLock);
	//	EptMapPage(&g_ept_shadow, FALSE, GuestRegs->ebx, GuestRegs->ecx, EPTE_WRITE | EPTE_READ, CACHE_TYPE_WB, FALSE, &g_ShadowEptSpinLock);
	//}

	ULONG VirtualAddress = 0;

	if (0x30 == GuestRegs->eax)
	{

		VirtualAddress = GuestRegs->ebx;

		//TestFlush();
	}
}
//-----------------------------------------------------------------------------//