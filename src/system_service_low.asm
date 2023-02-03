public internal_syscall

ifdef RAX

.code

internal_syscall PROC

	mov eax, ecx  ; index

	mov r10, rdx  ; arg0
	mov rdx, r8   ; arg1
	mov r8, r9    ; arg2
	mov r9, [rsp + 28h]  ; arg3

	lea rsi, [rsp + 30h]  ; src
	sub rsp, 0A8h  ; allocate space for the last args (80h + 28h)
	lea rdi, [rsp + 28h]  ; dst
	mov rcx, 10h          ; counter
	rep movsq
	syscall
	add rsp, 0A8h
	ret

internal_syscall ENDP

else
ifdef EAX

.386
.model flat, stdcall
.code

internal_syscall PROC

	ret

internal_syscall ENDP

else

endif
endif

END
