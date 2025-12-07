; ===========================================================================
; Montgomery squaring otimizado para 4 limbs (256-bit)
; Explora simetria: a[i]*a[j] = a[j]*a[i], portanto calcula apenas uma vez
;
; Para processadores Ivy Bridge (sem BMI2/ADX)
; 
; Compila com: nasm -f bin -o mont_sqr_4limbs.bin mont_sqr_4limbs.asm
; ===========================================================================

BITS 64

; Windows x64 ABI:
; RCX = result (ponteiro para 4 uint64)
; RDX = a (ponteiro para 4 uint64) - operando a ser elevado ao quadrado
; R8  = n (ponteiro para 4 uint64)
; R9  = n0 (int64, -n^-1 mod 2^64)

section .text
global _start

_start:
mont_sqr_4limbs:
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
    mov r14, r8         ; r14 = n
    mov r15, r9         ; r15 = n0
    
    ; Aloca t[9] na stack (9 * 8 = 72 bytes, alinhado a 16 = 80)
    sub rsp, 80
    
    ; Inicializa t[0..8] = 0
    xor rax, rax
    mov [rsp], rax
    mov [rsp+8], rax
    mov [rsp+16], rax
    mov [rsp+24], rax
    mov [rsp+32], rax
    mov [rsp+40], rax
    mov [rsp+48], rax
    mov [rsp+56], rax
    mov [rsp+64], rax
    
    ; rbx = ponteiro para t[]
    mov rbx, rsp
    
    ; ========================================================================
    ; FASE 1: Calcula produtos cruzados (off-diagonal) * 2
    ; a[0]*a[1], a[0]*a[2], a[0]*a[3], a[1]*a[2], a[1]*a[3], a[2]*a[3]
    ; ========================================================================
    
    ; --- a[0] * a[1..3] ---
    mov r8, [r13]           ; r8 = a[0]
    
    mov rax, r8
    mul qword [r13+8]       ; a[0] * a[1]
    mov [rbx+8], rax        ; t[1]
    mov r10, rdx            ; carry
    
    mov rax, r8
    mul qword [r13+16]      ; a[0] * a[2]
    add rax, r10
    adc rdx, 0
    mov [rbx+16], rax       ; t[2]
    mov r10, rdx
    
    mov rax, r8
    mul qword [r13+24]      ; a[0] * a[3]
    add rax, r10
    adc rdx, 0
    mov [rbx+24], rax       ; t[3]
    mov [rbx+32], rdx       ; t[4]
    
    ; --- a[1] * a[2..3] ---
    mov r8, [r13+8]         ; r8 = a[1]
    
    mov rax, r8
    mul qword [r13+16]      ; a[1] * a[2]
    add [rbx+24], rax       ; t[3] +=
    adc rdx, 0
    mov r10, rdx
    
    mov rax, r8
    mul qword [r13+24]      ; a[1] * a[3]
    add rax, r10
    adc rdx, 0
    add [rbx+32], rax       ; t[4] +=
    adc rdx, 0
    mov [rbx+40], rdx       ; t[5]
    
    ; --- a[2] * a[3] ---
    mov rax, [r13+16]
    mul qword [r13+24]      ; a[2] * a[3]
    add [rbx+40], rax       ; t[5] +=
    adc rdx, 0
    mov [rbx+48], rdx       ; t[6]
    
    ; ========================================================================
    ; FASE 2: Dobra os produtos cruzados (t *= 2)
    ; ========================================================================
    mov rax, [rbx+8]
    add [rbx+8], rax
    mov rax, [rbx+16]
    adc [rbx+16], rax
    mov rax, [rbx+24]
    adc [rbx+24], rax
    mov rax, [rbx+32]
    adc [rbx+32], rax
    mov rax, [rbx+40]
    adc [rbx+40], rax
    mov rax, [rbx+48]
    adc [rbx+48], rax
    adc qword [rbx+56], 0
    
    ; ========================================================================
    ; FASE 3: Adiciona os quadrados da diagonal (a[i]^2)
    ; ========================================================================
    mov rax, [r13]
    mul rax                 ; a[0]^2
    add [rbx], rax
    adc [rbx+8], rdx
    adc qword [rbx+16], 0
    
    mov rax, [r13+8]
    mul rax                 ; a[1]^2
    add [rbx+16], rax
    adc [rbx+24], rdx
    adc qword [rbx+32], 0
    
    mov rax, [r13+16]
    mul rax                 ; a[2]^2
    add [rbx+32], rax
    adc [rbx+40], rdx
    adc qword [rbx+48], 0
    
    mov rax, [r13+24]
    mul rax                 ; a[3]^2
    add [rbx+48], rax
    adc [rbx+56], rdx
    adc qword [rbx+64], 0
    
    ; ========================================================================
    ; FASE 4: Montgomery reduction (igual ao mont_mul)
    ; ========================================================================
    
    ; --- i = 0 ---
    mov rax, [rbx]
    imul rax, r15           ; m = t[0] * n0
    mov rsi, rax            ; rsi = m
    
    mul qword [r14]         ; m * n[0]
    add [rbx], rax
    adc rdx, 0
    mov r10, rdx
    
    mov rax, rsi
    mul qword [r14+8]
    add rax, r10
    adc rdx, 0
    add [rbx+8], rax
    adc rdx, 0
    mov r10, rdx
    
    mov rax, rsi
    mul qword [r14+16]
    add rax, r10
    adc rdx, 0
    add [rbx+16], rax
    adc rdx, 0
    mov r10, rdx
    
    mov rax, rsi
    mul qword [r14+24]
    add rax, r10
    adc rdx, 0
    add [rbx+24], rax
    adc rdx, 0
    add [rbx+32], rdx
    adc qword [rbx+40], 0
    
    ; --- i = 1 ---
    mov rax, [rbx+8]
    imul rax, r15
    mov rsi, rax
    
    mul qword [r14]
    add [rbx+8], rax
    adc rdx, 0
    mov r10, rdx
    
    mov rax, rsi
    mul qword [r14+8]
    add rax, r10
    adc rdx, 0
    add [rbx+16], rax
    adc rdx, 0
    mov r10, rdx
    
    mov rax, rsi
    mul qword [r14+16]
    add rax, r10
    adc rdx, 0
    add [rbx+24], rax
    adc rdx, 0
    mov r10, rdx
    
    mov rax, rsi
    mul qword [r14+24]
    add rax, r10
    adc rdx, 0
    add [rbx+32], rax
    adc rdx, 0
    add [rbx+40], rdx
    adc qword [rbx+48], 0
    
    ; --- i = 2 ---
    mov rax, [rbx+16]
    imul rax, r15
    mov rsi, rax
    
    mul qword [r14]
    add [rbx+16], rax
    adc rdx, 0
    mov r10, rdx
    
    mov rax, rsi
    mul qword [r14+8]
    add rax, r10
    adc rdx, 0
    add [rbx+24], rax
    adc rdx, 0
    mov r10, rdx
    
    mov rax, rsi
    mul qword [r14+16]
    add rax, r10
    adc rdx, 0
    add [rbx+32], rax
    adc rdx, 0
    mov r10, rdx
    
    mov rax, rsi
    mul qword [r14+24]
    add rax, r10
    adc rdx, 0
    add [rbx+40], rax
    adc rdx, 0
    add [rbx+48], rdx
    adc qword [rbx+56], 0
    
    ; --- i = 3 ---
    mov rax, [rbx+24]
    imul rax, r15
    mov rsi, rax
    
    mul qword [r14]
    add [rbx+24], rax
    adc rdx, 0
    mov r10, rdx
    
    mov rax, rsi
    mul qword [r14+8]
    add rax, r10
    adc rdx, 0
    add [rbx+32], rax
    adc rdx, 0
    mov r10, rdx
    
    mov rax, rsi
    mul qword [r14+16]
    add rax, r10
    adc rdx, 0
    add [rbx+40], rax
    adc rdx, 0
    mov r10, rdx
    
    mov rax, rsi
    mul qword [r14+24]
    add rax, r10
    adc rdx, 0
    add [rbx+48], rax
    adc rdx, 0
    add [rbx+56], rdx
    adc qword [rbx+64], 0
    
    ; ========================================================================
    ; COPIA RESULTADO: result[j] = t[4+j]
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
    ; SUBTRAÇÃO CONDICIONAL
    ; ========================================================================
    mov rax, [rbx+64]
    test rax, rax
    jnz .do_sub
    
    mov rax, [r12+24]
    cmp rax, [r14+24]
    ja .do_sub
    jb .done
    
    mov rax, [r12+16]
    cmp rax, [r14+16]
    ja .do_sub
    jb .done
    
    mov rax, [r12+8]
    cmp rax, [r14+8]
    ja .do_sub
    jb .done
    
    mov rax, [r12]
    cmp rax, [r14]
    jb .done
    
.do_sub:
    mov rax, [r12]
    sub rax, [r14]
    mov [r12], rax
    
    mov rax, [r12+8]
    sbb rax, [r14+8]
    mov [r12+8], rax
    
    mov rax, [r12+16]
    sbb rax, [r14+16]
    mov [r12+16], rax
    
    mov rax, [r12+24]
    sbb rax, [r14+24]
    mov [r12+24], rax
    
.done:
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
