//  [5/4/2015 uty]
//  [10/29/2017 uty]
#ifndef _VMX_ASM_H_
#define _VMX_ASM_H_
//-----------------------------------------------------------------------------//
//VOID VmxTurnOn (PHYSICAL_ADDRESS VmxonPA);
//VOID VmxPtrld (PHYSICAL_ADDRESS VmcsPA);
//VOID VmxClear(PHYSICAL_ADDRESS VmcsPA);

ULONG VmxTurnOn(ULONG phyvmxonhigh, ULONG phyvmxonlow);
ULONG VmxClear(ULONG phyvmxonhigh, ULONG phyvmxonlow);
ULONG VmxPtrld(ULONG phyvmxonhigh, ULONG phyvmxonlow);
VOID VmxWrite (ULONG Field, ULONG Value);
ULONG VmxRead (ULONG Field);
VOID VmxLaunch (VOID);

VOID VmxExitHandler (VOID);
//-----------------------------------------------------------------------------//
#endif