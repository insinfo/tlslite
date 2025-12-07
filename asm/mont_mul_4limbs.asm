; ===========================================================================
; Montgomery multiplication otimizado para 4 limbs (256-bit)
; Loops completamente desenrolados, sem overhead de branches
;
; Para processadores Ivy Bridge (sem BMI2/ADX)
; 
; Compila com: nasm -f bin -o mont_mul_4limbs.bin mont_mul_4limbs.asm
; ===========================================================================

BITS 64

; Windows x64 ABI:
; RCX = result (ponteiro para 4 uint64)
; RDX = a (ponteiro para 4 uint64)  
; R8  = b (ponteiro para 4 uint64)
; R9  = n (ponteiro para 4 uint64)
; [RSP+40] = n0 (int64, -n^-1 mod 2^64)
; [RSP+48] = numLimbs (ignorado, sempre 4)

section .text
global _start

_start:
mont_mul_4limbs:
    ; Prólogo
    push rbx
    push rbp
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    
    ; Salva parâmetros
    mov r12, rcx        ; r12 = result
    mov r13, rdx        ; r13 = a
    mov r14, r8         ; r14 = b
    mov r15, r9         ; r15 = n
    mov rsi, [rsp+0x68] ; rsi = n0 (após 8 pushes = 64 bytes + shadow space 32 + 8 = 0x68)
    
    ; Aloca t[9] na stack (9 * 8 = 72 bytes, alinhado a 16 = 80)
    sub rsp, 80
    
    ; Inicializa t[0..8] = 0 (movaps descomentado para não quebrar em desalinhamento)
    xor rax, rax
    mov [rsp], rax        ; t[0]
    mov [rsp+8], rax      ; t[1]
    mov [rsp+16], rax     ; t[2]
    mov [rsp+24], rax     ; t[3]
    mov [rsp+32], rax     ; t[4]
    mov [rsp+40], rax     ; t[5]
    mov [rsp+48], rax     ; t[6]
    mov [rsp+56], rax     ; t[7]
    mov [rsp+64], rax     ; t[8]
    
    ; rbx = ponteiro para t[]
    mov rbx, rsp
    
    ; ========================================================================
    ; CIOS Loop completamente desenrolado para 4 limbs
    ; ========================================================================
    
    ; ------------------------------------------------------------------------
    ; i = 0
    ; ------------------------------------------------------------------------
    mov r8, [r13]           ; r8 = a[0]
    
    ; Fase 1: t += a[0] * b[j] para j = 0..3
    mov rax, r8
    mul qword [r14]         ; rdx:rax = a[0] * b[0]
    add [rbx], rax
    adc rdx, 0
    mov r10, rdx            ; carry
    
    mov rax, r8
    mul qword [r14+8]       ; a[0] * b[1]
    add rax, r10
    adc rdx, 0
    add [rbx+8], rax
    adc rdx, 0
    mov r10, rdx
    
    mov rax, r8
    mul qword [r14+16]      ; a[0] * b[2]
    add rax, r10
    adc rdx, 0
    add [rbx+16], rax
    adc rdx, 0
    mov r10, rdx
    
    mov rax, r8
    mul qword [r14+24]      ; a[0] * b[3]
    add rax, r10
    adc rdx, 0
    add [rbx+24], rax
    adc rdx, 0
    add [rbx+32], rdx
    adc qword [rbx+40], 0
    
    ; Fase 2: m = t[0] * n0, t += m * n[j]
    mov rax, [rbx]
    imul rax, rsi           ; m = t[0] * n0
    mov r8, rax             ; r8 = m
    
    mul qword [r15]         ; m * n[0]
    add [rbx], rax
    adc rdx, 0
    mov r10, rdx
    
    mov rax, r8
    mul qword [r15+8]       ; m * n[1]
    add rax, r10
    adc rdx, 0
    add [rbx+8], rax
    adc rdx, 0
    mov r10, rdx
    
    mov rax, r8
    mul qword [r15+16]      ; m * n[2]
    add rax, r10
    adc rdx, 0
    add [rbx+16], rax
    adc rdx, 0
    mov r10, rdx
    
    mov rax, r8
    mul qword [r15+24]      ; m * n[3]
    add rax, r10
    adc rdx, 0
    add [rbx+24], rax
    adc rdx, 0
    add [rbx+32], rdx
    adc qword [rbx+40], 0
    
    ; ------------------------------------------------------------------------
    ; i = 1
    ; ------------------------------------------------------------------------
    mov r8, [r13+8]         ; r8 = a[1]
    
    ; Fase 1: t[1..5] += a[1] * b[j]
    mov rax, r8
    mul qword [r14]
    add [rbx+8], rax
    adc rdx, 0
    mov r10, rdx
    
    mov rax, r8
    mul qword [r14+8]
    add rax, r10
    adc rdx, 0
    add [rbx+16], rax
    adc rdx, 0
    mov r10, rdx
    
    mov rax, r8
    mul qword [r14+16]
    add rax, r10
    adc rdx, 0
    add [rbx+24], rax
    adc rdx, 0
    mov r10, rdx
    
    mov rax, r8
    mul qword [r14+24]
    add rax, r10
    adc rdx, 0
    add [rbx+32], rax
    adc rdx, 0
    add [rbx+40], rdx
    adc qword [rbx+48], 0
    
    ; Fase 2: m = t[1] * n0
    mov rax, [rbx+8]
    imul rax, rsi
    mov r8, rax
    
    mul qword [r15]
    add [rbx+8], rax
    adc rdx, 0
    mov r10, rdx
    
    mov rax, r8
    mul qword [r15+8]
    add rax, r10
    adc rdx, 0
    add [rbx+16], rax
    adc rdx, 0
    mov r10, rdx
    
    mov rax, r8
    mul qword [r15+16]
    add rax, r10
    adc rdx, 0
    add [rbx+24], rax
    adc rdx, 0
    mov r10, rdx
    
    mov rax, r8
    mul qword [r15+24]
    add rax, r10
    adc rdx, 0
    add [rbx+32], rax
    adc rdx, 0
    add [rbx+40], rdx
    adc qword [rbx+48], 0
    
    ; ------------------------------------------------------------------------
    ; i = 2
    ; ------------------------------------------------------------------------
    mov r8, [r13+16]        ; r8 = a[2]
    
    mov rax, r8
    mul qword [r14]
    add [rbx+16], rax
    adc rdx, 0
    mov r10, rdx
    
    mov rax, r8
    mul qword [r14+8]
    add rax, r10
    adc rdx, 0
    add [rbx+24], rax
    adc rdx, 0
    mov r10, rdx
    
    mov rax, r8
    mul qword [r14+16]
    add rax, r10
    adc rdx, 0
    add [rbx+32], rax
    adc rdx, 0
    mov r10, rdx
    
    mov rax, r8
    mul qword [r14+24]
    add rax, r10
    adc rdx, 0
    add [rbx+40], rax
    adc rdx, 0
    add [rbx+48], rdx
    adc qword [rbx+56], 0
    
    mov rax, [rbx+16]
    imul rax, rsi
    mov r8, rax
    
    mul qword [r15]
    add [rbx+16], rax
    adc rdx, 0
    mov r10, rdx
    
    mov rax, r8
    mul qword [r15+8]
    add rax, r10
    adc rdx, 0
    add [rbx+24], rax
    adc rdx, 0
    mov r10, rdx
    
    mov rax, r8
    mul qword [r15+16]
    add rax, r10
    adc rdx, 0
    add [rbx+32], rax
    adc rdx, 0
    mov r10, rdx
    
    mov rax, r8
    mul qword [r15+24]
    add rax, r10
    adc rdx, 0
    add [rbx+40], rax
    adc rdx, 0
    add [rbx+48], rdx
    adc qword [rbx+56], 0
    
    ; ------------------------------------------------------------------------
    ; i = 3
    ; ------------------------------------------------------------------------
    mov r8, [r13+24]        ; r8 = a[3]
    
    mov rax, r8
    mul qword [r14]
    add [rbx+24], rax
    adc rdx, 0
    mov r10, rdx
    
    mov rax, r8
    mul qword [r14+8]
    add rax, r10
    adc rdx, 0
    add [rbx+32], rax
    adc rdx, 0
    mov r10, rdx
    
    mov rax, r8
    mul qword [r14+16]
    add rax, r10
    adc rdx, 0
    add [rbx+40], rax
    adc rdx, 0
    mov r10, rdx
    
    mov rax, r8
    mul qword [r14+24]
    add rax, r10
    adc rdx, 0
    add [rbx+48], rax
    adc rdx, 0
    add [rbx+56], rdx
    adc qword [rbx+64], 0
    
    mov rax, [rbx+24]
    imul rax, rsi
    mov r8, rax
    
    mul qword [r15]
    add [rbx+24], rax
    adc rdx, 0
    mov r10, rdx
    
    mov rax, r8
    mul qword [r15+8]
    add rax, r10
    adc rdx, 0
    add [rbx+32], rax
    adc rdx, 0
    mov r10, rdx
    
    mov rax, r8
    mul qword [r15+16]
    add rax, r10
    adc rdx, 0
    add [rbx+40], rax
    adc rdx, 0
    mov r10, rdx
    
    mov rax, r8
    mul qword [r15+24]
    add rax, r10
    adc rdx, 0
    add [rbx+48], rax
    adc rdx, 0
    add [rbx+56], rdx
    adc qword [rbx+64], 0
    
    ; ========================================================================
    ; Copia resultado: result[j] = t[4+j]
    ; ========================================================================
    mov rax, [rbx+32]
    mov [r12], rax
    mov rax, [rbx+40]
    mov [r12+8], rax
    mov rax, [rbx+48]
    mov [r12+16], rax
    mov rax, [rbx+56]
    mov [r12+24], rax
    
    ; ========================================================================
    ; Subtração condicional: if result >= n then result -= n
    ; ========================================================================
    
    ; Verifica carry em t[8]
    mov rax, [rbx+64]
    test rax, rax
    jnz .do_sub
    
    ; Compara result com n (de trás para frente)
    mov rax, [r12+24]
    cmp rax, [r15+24]
    ja .do_sub
    jb .done
    
    mov rax, [r12+16]
    cmp rax, [r15+16]
    ja .do_sub
    jb .done
    
    mov rax, [r12+8]
    cmp rax, [r15+8]
    ja .do_sub
    jb .done
    
    mov rax, [r12]
    cmp rax, [r15]
    jb .done
    
.do_sub:
    ; result -= n (desenrolado)
    mov rax, [r12]
    sub rax, [r15]
    mov [r12], rax
    
    mov rax, [r12+8]
    sbb rax, [r15+8]
    mov [r12+8], rax
    
    mov rax, [r12+16]
    sbb rax, [r15+16]
    mov [r12+16], rax
    
    mov rax, [r12+24]
    sbb rax, [r15+24]
    mov [r12+24], rax
    
.done:
    ; Epílogo
    add rsp, 80
    
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    
    ret
