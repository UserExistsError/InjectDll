#if defined(_M_IX86)

void ExecuteNative64(void *shellcode, void *arg)
{
    unsigned long saved_esp = 0;
    __asm {
            mov saved_esp, esp
            and esp, 0xfffffff0

            push 033h                        ; CS reg value for 64 bit
            call push_eip
        push_eip:
            add[esp], 5; 5 is size of add / retf
            retf

            ; this executes in 64 bit mode
            sub esp, 020h                    ; give shellcode some room to play
            mov eax, shellcode
            mov ecx, arg
            call eax
            add esp, 020h

            mov ecx, 02bh
            mov ss, cx                       ; Windows does this but seems to be a nop?

            call push_rip                    ; call pushes a 64 bit address here
        push_rip:
            mov dword ptr[esp + 4], 023h     ; CS reg for 32 bit
            add dword ptr[esp], 0dh          ; 0xd is size of mov / add / retf
            retf

            ; back to wow64
            mov esp, saved_esp
    }
}
#endif
