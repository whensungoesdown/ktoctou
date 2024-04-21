; Copyright notice
; ================
; 
; Copyright (C) 2010
;     Lorenzo  Martignoni <martignlo@gmail.com>
;     Roberto  Paleari    <roberto.paleari@gmail.com>
;     Aristide Fattori    <joystick@security.dico.unimi.it>
; 
; This program is free software: you can redistribute it and/or modify it under
; the terms of the GNU General Public License as published by the Free Software
; Foundation, either version 3 of the License, or (at your option) any later
; version.
; 
; HyperDbg is distributed in the hope that it will be useful, but WITHOUT ANY
; WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
; A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
; 
; You should have received a copy of the GNU General Public License along with
; this program. If not, see <http://www.gnu.org/licenses/>.
; 

.686p
.model flat,StdCall

EXTERN doStartVMX@4: PROC

;doStartVMX PROTO C

.CODE


	
CmInitSpinLock PROC StdCall lck
	mov	eax, lck
	and	dword ptr [eax], 0

	ret
CmInitSpinLock ENDP

CmAcquireSpinLock PROC StdCall lck
	mov	eax, lck
do_lock:
	lock	bts dword ptr [eax], 0
	jc	do_lock

	ret
CmAcquireSpinLock ENDP

CmReleaseSpinLock PROC StdCall lck
	mov	eax, lck
	lock	btr dword ptr [eax], 0

	ret
CmReleaseSpinLock ENDP



StartVMX PROC
	;int 3
	push eax
	push ecx
	push edx
	push ebx
	push ebp
	push esi
	push edi

			
	sub esp, 28h

	;mov rcx, rsp
	push esp


	call doStartVMX@4
	;jmp StartVMXBack  ; test

StartVMX ENDP


StartVMXBack PROC

	;int 3
	add esp, 28h

	pop edi
	pop esi
	pop ebp
	pop ebx
	pop edx
	pop ecx
	pop eax
	
	ret
	
StartVMXBack ENDP


_INVD PROC

	invd
	ret
	
_INVD ENDP


END