#include <ntddk.h>
#include "smap.h"
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

inline BOOLEAN user_mode(int cs)
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