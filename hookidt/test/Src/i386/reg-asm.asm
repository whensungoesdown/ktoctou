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
option casemap:none

.CODE
	
RegGetFlags PROC
	pushfd
	pop eax
	ret
RegGetFlags ENDP

RegSetFlags PROC StdCall _flags
	mov eax, _flags
	push eax
	popfd
	ret
RegSetFlags ENDP

RegGetCr0 PROC
	mov eax, cr0
	ret
RegGetCr0 ENDP

RegSetCr0 PROC StdCall _CR0
	mov eax, _CR0
	mov cr0, eax
	ret
RegSetCr0 ENDP
	
RegGetCr2 PROC
	mov eax, cr2
	ret
RegGetCr2 ENDP

RegGetCr3 PROC
	mov eax, cr3
	ret
RegGetCr3 ENDP

RegGetCr4 PROC
	mov eax, cr4
	ret
RegGetCr4 ENDP

RegSetCr4 PROC StdCall _CR4
	mov eax, _CR4
	mov cr4, eax
	ret
RegSetCr4 ENDP

;	Writes the contents of registers EDX:EAX into the 64-bit model specific
;	register (MSR) specified in the ECX register. The contents of the EDX
;	register are copied to high-order 32 bits of the selected MSR and the
;	contents of the EAX register are copied to low-order 32 bits of the MSR.
;		msr.Hi <-- EDX
;		msr.Lo <-- EAX
;
WriteMSR PROC StdCall encoding, _highpart, _lowpart
	pushad

	mov ecx, encoding
	mov edx, _highpart
	mov eax, _lowpart

	wrmsr

	popad

	ret
WriteMSR ENDP	

RegGetCs PROC
	mov ax, cs
	ret
RegGetCs ENDP

RegGetDs PROC
	mov ax, ds
	ret
RegGetDs ENDP

RegGetEs PROC
	mov ax, es
	ret
RegGetEs ENDP

RegGetFs PROC
	mov ax, fs
	ret
RegGetFs ENDP

RegGetGs PROC
	mov ax, gs
	ret
RegGetGs ENDP

RegGetSs PROC
	mov ax, ss
	ret
RegGetSs ENDP

RegGetTr PROC
	str ax
	ret
RegGetTr ENDP

RegGetLdtr PROC
	sldt eax
	ret
RegGetLdtr ENDP

ReadMSRToLarge PROC StdCall _reg
	mov ecx, _reg
	rdmsr ; MSR[ecx] --> edx:eax
	ret
ReadMSRToLarge ENDP

RegSetIdtr PROC StdCall _base, _limit
	push	_base
	shl	_limit, 16
	push	_limit
	lidt	fword ptr [esp+2]
	pop	eax
	pop	eax
	ret
RegSetIdtr ENDP

; uty add

GetIdtBase	Proc
		Local	idtr[6]:BYTE
		sidt	idtr
		mov	eax,dword ptr idtr[2]
		ret
GetIdtBase	EndP

GetIdtLimit	Proc
		Local	idtr[6]:BYTE
		sidt	idtr
		mov	ax,word ptr idtr[0]
		ret
GetIdtLimit	EndP

GetGdtBase	Proc
		Local	gdtr[6]:BYTE
		sgdt	gdtr
		mov	eax,dword ptr gdtr[2]
		ret
GetGdtBase	EndP

GetGdtLimit	Proc
		Local	gdtr[6]:BYTE
		sgdt	gdtr
		mov	ax,word ptr gdtr[0]
		ret
GetGdtLimit	EndP

SetSmap Proc
		cli
		push eax
		mov eax, cr4
		or eax, 200000h
		mov cr4, eax
		pop eax
		sti
		ret
SetSmap EndP

END
