//  [5/4/2015 uty]
#ifndef _REGS_ASM_H_
#define _REGS_ASM_H_
//-----------------------------------------------------------------------------//
ULONG RegGetCr0 (VOID);
ULONG RegGetCr3 (VOID);
ULONG RegGetCr4 (VOID);
VOID RegSetCr0(ULONG);
VOID RegSetCr3(ULONG);
VOID RegSetCr4(ULONG);
VOID RegSetBitCr4 (ULONG mask);
VOID RegClearBitCr4 (ULONG mask);

ULONG RegGetEflags(VOID);
VOID RegSetEflags(ULONG flags);

USHORT RegGetCs(VOID);
USHORT RegGetDs(VOID);
USHORT RegGetEs(VOID);
USHORT RegGetSs(VOID);
USHORT RegGetFs(VOID);
USHORT RegGetGs(VOID);

ULONG GetIdtBase(VOID);
USHORT GetIdtLimit(VOID);
ULONG GetGdtBase(VOID);
USHORT GetGdtLimit(VOID);
USHORT GetLdtr(VOID);
USHORT GetTr(VOID);

VOID
GetCpuIdInfo (
  __in ULONG32 fn,
  __out PULONG32 ret_eax,
  __out PULONG32 ret_ebx,
  __out PULONG32 ret_ecx,
  __out PULONG32 ret_edx
  );


VOID
ReloadGdtr (
	PVOID GdtBase,
	ULONG GdtLimit
	);

VOID
ReloadIdtr (
	PVOID IdtBase,
	ULONG IdtLimit
	);

//-----------------------------------------------------------------------------//
#endif