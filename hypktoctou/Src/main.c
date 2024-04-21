//  [5/2/2015 uty]
#include <ntddk.h>
#include "vmminitstate.h"
#include "i386/common-asm.h"
#include "vmx.h"
//#include "ept.h"
#include "powercallback.h"
#include "idthook.h"
#include "smap.h"
#include "structs.h"
#include "helper.h"
//-----------------------------------------------------------------------------//
extern KSPIN_LOCK g_SpinkLock;

PKEFLUSHSINGLETB pKeFlushSingleTb = NULL;
PKEFLUSHENTIRETB pKeFlushEntireTb = NULL;
//-----------------------------------------------------------------------------//
NTSTATUS
RunOnProcessor (
	__in ULONG ProcessorNumber
	)
{
	KIRQL OldIrql;

	KeSetSystemAffinityThread((KAFFINITY)(1 << ProcessorNumber));
	
	OldIrql = KeRaiseIrqlToDpcLevel();

	//
	// Initialize VMX on every CPU
	//

	StartVMX();

	KeLowerIrql(OldIrql);

	KeRevertToUserAffinityThread();

	return STATUS_SUCCESS;
}
//-----------------------------------------------------------------------------//
DEV_EXT g_DevExt = {0};
//-----------------------------------------------------------------------------//
NTSTATUS
DriverEntry (
	__in PDRIVER_OBJECT DriverObject,
	__in PUNICODE_STRING RegistryPath
	)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	KAFFINITY Affinity = 0;
	LONG i = 0;


	KeInitializeSpinLock(&g_SpinkLock);

	HookInt0E(); 

	HookKiSystemCallExit2();

	pKeFlushSingleTb = (PKEFLUSHSINGLETB)0x804fb482;
	pKeFlushEntireTb = (PKEFLUSHENTIRETB)0x804fb2b4;

	FindTargetProcess();

	//
	// initialize hypervisor

	Affinity = KeQueryActiveProcessors();

	DbgPrint("KeQueryActiveProcessors: %x\n", Affinity);

	for (i = 0; i < 32; i++)
	{
		if (1 == _bittest(&Affinity, i))
		{
			Status = InitializeVMMInitState(&g_VMMInitState[i]);

			DbgPrint("CPU %d\n", i);

			Status = RunOnProcessor(i);
			if (STATUS_SUCCESS != Status)
			{
				DbgPrint("RunOnProcessor failed on processor %d\n", i);
				goto Exit0;
			}
		}
	}


	Status = STATUS_SUCCESS;
Exit0:

	if (STATUS_SUCCESS != Status)
	{
		for (i = 0; i < KeNumberProcessors; i++)
		{
			UninitializeVMMInitState(&g_VMMInitState[i]);
		}
	}
	

	return Status;
}
//-----------------------------------------------------------------------------//