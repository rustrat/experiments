.code
get_peb PROC
    mov rax, GS:[60h]
    ret
get_peb ENDP

END