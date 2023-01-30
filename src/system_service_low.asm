ifdef RAX

.code

internal_syscall PROC

	mov eax, ecx
	mov r10, rdx
	mov rdx, r8
	mov r8, r9
	mov r9, [rsp + 28]
	mov rcx, [rsp + 30]
	mov [rsp + 28], rcx
	mov rcx, [rsp + 38]
	mov [rsp + 30], rcx
	mov rcx, [rsp + 40]
	mov [rsp + 38], rcx
	syscall
	ret

internal_syscall ENDP

else

.386
.model flat, stdcall
.code

internal_syscall PROC

	ret

internal_syscall ENDP

endif

END
