//  [5/15/2015 uty]
#ifndef _COMMON_H_
#define _COMMON_H_
//-----------------------------------------------------------------------------//
/* Set a single bit of a DWORD argument */
VOID CmSetBit(ULONG * dword, ULONG bit);
VOID CmClearBit16(USHORT* word, ULONG bit);
//-----------------------------------------------------------------------------//
// NTSTATUS
// UtLockPagablePage (
// 	__in PVOID Address	// address within the page
// 	);
//-----------------------------------------------------------------------------//
#endif