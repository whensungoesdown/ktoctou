//  [5/15/2015 uty]
#include <ntddk.h>
#include "common.h"
#include "vmx.h"
#include "i386/vmx-asm.h"
//-----------------------------------------------------------------------------//
NTSTATUS
ShadowHookInit (
	VOID
	)
{
	ULONG Temp = 0;

	Temp = (ULONG)VmxRead(EXCEPTION_BITMAP);
	CmSetBit(&Temp, TRAP_DEBUG);

	VmxWrite(EXCEPTION_BITMAP, Temp);

	return STATUS_SUCCESS;
}
//-----------------------------------------------------------------------------//