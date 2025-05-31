.data
    Hooker QWORD 0
.const
    

.code
    ICHookerLowLevelPartSetHooker PROC
        mov Hooker,rcx
        ret
    ICHookerLowLevelPartSetHooker ENDP

    ICHookerLowLevelPart PROC        
        

        push rax ;anti-recursion
                mov rax,gs:[030h]
                test byte ptr [rax+02ECh],01
                je notrecursion
                    pop rax
                    jmp r10
                notrecursion:
        pop rax
        
        ;pushing old rsp
        push rsp
        ;return addr space
        sub rsp,08h
        ;pushing regs
        push rax
        push rcx
        push rdx
        push rbx
        push rbp
        push rsi
        push rdi
        push r8
        push r9
        push r10
        push r11
        push r12
        push r13
        push r14
        push r15
        sub rsp,010h
        movdqu [rsp],xmm0
        sub rsp,010h
        movdqu [rsp],xmm1
        sub rsp,010h
        movdqu [rsp],xmm2
        sub rsp,010h
        movdqu [rsp],xmm3
        sub rsp,010h
        movdqu [rsp],xmm4
        sub rsp,010h
        movdqu [rsp],xmm5
        sub rsp,010h
        movdqu [rsp],xmm6
        sub rsp,010h
        movdqu [rsp],xmm7

            push gs:[2e0h]
            push gs:[2d8h]
            mov gs:[2e0h], rsp
            mov gs:[2d8h], r10 

            mov rax,gs:[030h] ;disabling IC
            mov byte ptr [rax+02ech],1

            mov rcx,rsp
            add rcx,10h
            sub rsp,30h
            and rsp,0fffffffffffffff0h
            
            call Hooker

            mov rax,gs:[030h] ;enabling IC
            mov byte ptr [rax+02ech],0

            mov rsp, gs:[2e0h]
            mov r10, gs:[2d8h]
            pop gs:[2e0h]
            pop gs:[2d8h]

        movdqu [rsp],xmm7
        add rsp,010h
        movdqu [rsp],xmm6
        add rsp,010h
        movdqu [rsp],xmm5
        add rsp,010h
        movdqu [rsp],xmm4
        add rsp,010h
        movdqu [rsp],xmm3
        add rsp,010h
        movdqu [rsp],xmm2
        add rsp,010h
        movdqu [rsp],xmm1
        add rsp,010h
        movdqu [rsp],xmm0
        add rsp,010h
        pop r15
        pop r14
        pop r13
        pop r12
        pop r11
        pop r10
        pop r9
        pop r8
        pop rdi
        pop rsi
        pop rbp
        pop rbx
        pop rdx
        pop rcx
        pop rax
        ;mov rsp,[rsp] ;real bad idea
        add rsp,10h
        recursion:
        jmp QWORD PTR [rsp-010h]
    ICHookerLowLevelPart ENDP



END