.MODEL FLAT, C
.code
get_peb PROC
    ASSUME FS:NOTHING
    mov eax, FS:[30h]
    ASSUME FS:ERROR
    ret
get_peb ENDP

END