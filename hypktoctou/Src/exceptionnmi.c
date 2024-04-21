//  [5/15/2015 uty]
#include <ntddk.h>
#include "vmx.h"
#include "ept.h"
#include "i386/vmx-asm.h"
#include "cpu.h"
#include "vmminitstate.h"
//-----------------------------------------------------------------------------//
VOID
HandleExceptionNmi (
	VOID
	)
{
	ULONG trap = 0;
	//ULONG eFlags = 0;
	ULONG64 ExitInterruptionInformation = 0;

	ExitInterruptionInformation = VmxRead(VM_EXIT_INTR_INFO);
	trap = (ULONG)ExitInterruptionInformation & INTR_INFO_VECTOR_MASK;

	switch (trap)
	{
	case TRAP_PAGE_FAULT:
		break;
	case TRAP_DEBUG:
		{
			//PVMM_INIT_STATE pCurrentVMMInitState = NULL;
			//pCurrentVMMInitState = &g_VMMInitState[KeGetCurrentProcessorNumber()];

			//DbgPrint("TRAP_DEBUG g_EptViolationStepping %d\n", pCurrentVMMInitState->EptViolationStepping);

			//eFlags = (ULONG)VmxRead(GUEST_RFLAGS);
			//eFlags = eFlags & ~FLAGS_TF_MASK & ~FLAGS_RF_MASK;
			//VmxWrite(GUEST_RFLAGS,eFlags);

			//if (pCurrentVMMInitState->EptViolationStepping)
			//{
			//	pCurrentVMMInitState->EptViolationStepping = FALSE;
			//	EptSetPageAccess(&g_ept_shadow, FALSE, g_TmpShadowHookAddress & 0xFFFFFFFFFFFFF000, EPTE_READ | EPTE_WRITE, &g_ShadowEptSpinLock);
			//	pCurrentVMMInitState->ShadowEpt = FALSE;
			//	SwitchToEPTOriginal(pCurrentVMMInitState);
			//}
			break;
		}
	default:
		break;
	}
}
//-----------------------------------------------------------------------------//