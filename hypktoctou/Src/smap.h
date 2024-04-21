#ifndef _SMAP_H_
#define _SMAP_H_
//-----------------------------------------------------------------------------//
int HookKiSystemCallExit2();
LONG HandleSmap(VOID);
VOID ReleasePage (VOID);
VOID ReleaseSmapPages_Cr3_All();
//-----------------------------------------------------------------------------//
#endif