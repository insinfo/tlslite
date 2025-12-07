; Montgomery Multiplication v3 - CORRIGIDO
; Compile: nasm -f bin mont_mul_v3.asm -o mont_mul_v3.bin
;
; Windows x64 ABI:
;   RCX = result pointer 
;   RDX = a pointer
;   R8  = b pointer
;   R9  = n pointer (modulus)
;   [RSP+40+64] = n0 (montgomery constant) -> [RSP+0x68] após pushes
;   [RSP+48+64] = numLimbs                 -> [RSP+0x70] após pushes
;
; Algoritmo CIOS (Coarsely Integrated Operand Scanning)

BITS 64

mont_mul:
    ; Salva registradores callee-saved
    push rbx
    push rbp
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    ; 8 pushes = 64 bytes
    
    ; Salva argumentos em registradores callee-saved
    mov r12, rcx            ; r12 = result ptr
    mov r13, rdx            ; r13 = a ptr
    mov r14, r8             ; r14 = b ptr
    mov r15, r9             ; r15 = n ptr
    
    ; Carrega argumentos da stack
    mov rsi, [rsp + 0x68]   ; rsi = n0
    mov rdi, [rsp + 0x70]   ; rdi = numLimbs
    
    ; Aloca array t[] na stack: (2*numLimbs + 1) * 8 bytes, alinhado 16
    lea rax, [rdi*2 + 1]
    shl rax, 3              ; bytes = qwords * 8
    add rax, 15
    and rax, -16            ; alinha 16 bytes
    sub rsp, rax
    mov rbx, rsp            ; rbx = base de t[]
    
    ; Salva tamanho alocado para cleanup
    push rax                ; [rsp] = t_size
    
    ; Inicializa t[] com zeros
    ; Usando rep stosq que é mais eficiente
    mov rcx, rdi            ; rcx = numLimbs
    shl rcx, 1              ; rcx = 2*numLimbs
    inc rcx                 ; rcx = 2*numLimbs + 1
    push rdi                ; preserva numLimbs
    mov rdi, rbx            ; rdi = destino (t[])
    xor eax, eax            ; valor a escrever = 0
    rep stosq               ; preenche rcx qwords com 0
    pop rdi                 ; restaura numLimbs
    
    ; ========================================================================
    ; LOOP EXTERNO: for i = 0 to numLimbs-1
    ; ========================================================================
    xor ebp, ebp            ; rbp = i = 0 (usando rbp para índice i)
    
.outer_loop:
    cmp rbp, rdi            ; i < numLimbs?
    jge .outer_done
    
    ; ------------------------------------------------------------------------
    ; FASE 1: t += a[i] * b[j] para j = 0..numLimbs-1
    ; ------------------------------------------------------------------------
    ; Carrega a[i] uma vez
    mov r8, [r13 + rbp*8]   ; r8 = a[i]
    
    xor r9d, r9d            ; r9 = j = 0
    xor r10d, r10d          ; r10 = carry = 0
    
.phase1_loop:
    cmp r9, rdi             ; j < numLimbs?
    jge .phase1_done
    
    ; Calcula: (carry, t[i+j]) = t[i+j] + a[i]*b[j] + carry
    mov rax, r8             ; rax = a[i]
    mul qword [r14 + r9*8]  ; rdx:rax = a[i] * b[j]
    
    ; Calcula índice i+j
    lea rcx, [rbp + r9]     ; rcx = i + j
    
    ; Soma t[i+j]
    add rax, [rbx + rcx*8]
    adc rdx, 0
    
    ; Soma carry anterior
    add rax, r10
    adc rdx, 0
    
    ; Armazena resultado
    mov [rbx + rcx*8], rax  ; t[i+j] = low part
    mov r10, rdx            ; carry = high part
    
    inc r9                  ; j++
    jmp .phase1_loop
    
.phase1_done:
    ; Propaga carry para t[i + numLimbs] e t[i + numLimbs + 1]
    lea rcx, [rbp + rdi]    ; rcx = i + numLimbs
    add [rbx + rcx*8], r10  ; t[i+numLimbs] += carry
    adc qword [rbx + rcx*8 + 8], 0  ; propaga para próximo
    
    ; ------------------------------------------------------------------------
    ; FASE 2: m = t[i] * n0 mod 2^64, t += m * n[j]
    ; ------------------------------------------------------------------------
    ; Calcula m = t[i] * n0
    mov rax, [rbx + rbp*8]  ; rax = t[i]
    imul rax, rsi           ; rax = t[i] * n0 (mod 2^64)
    mov r8, rax             ; r8 = m
    
    xor r9d, r9d            ; r9 = j = 0  
    xor r10d, r10d          ; r10 = carry = 0
    
.phase2_loop:
    cmp r9, rdi             ; j < numLimbs?
    jge .phase2_done
    
    ; Calcula: (carry, t[i+j]) = t[i+j] + m*n[j] + carry
    mov rax, r8             ; rax = m
    mul qword [r15 + r9*8]  ; rdx:rax = m * n[j]
    
    lea rcx, [rbp + r9]     ; rcx = i + j
    
    add rax, [rbx + rcx*8]
    adc rdx, 0
    
    add rax, r10
    adc rdx, 0
    
    mov [rbx + rcx*8], rax
    mov r10, rdx
    
    inc r9
    jmp .phase2_loop
    
.phase2_done:
    ; Propaga carry
    lea rcx, [rbp + rdi]
    add [rbx + rcx*8], r10
    adc qword [rbx + rcx*8 + 8], 0
    
    inc rbp                 ; i++
    jmp .outer_loop
    
.outer_done:
    ; ========================================================================
    ; COPIA RESULTADO: result[j] = t[numLimbs + j] para j = 0..numLimbs-1
    ; ========================================================================
    xor r9d, r9d            ; j = 0
    
.copy_loop:
    cmp r9, rdi
    jge .copy_done
    
    lea rcx, [rdi + r9]     ; rcx = numLimbs + j
    mov rax, [rbx + rcx*8]  ; rax = t[numLimbs + j]
    mov [r12 + r9*8], rax   ; result[j] = rax
    
    inc r9
    jmp .copy_loop
    
.copy_done:
    ; ========================================================================
    ; SUBTRAÇÃO CONDICIONAL: if result >= n then result -= n
    ; ========================================================================
    
    ; Primeiro verifica se há carry em t[2*numLimbs]
    ; Se t[2*numLimbs] != 0, precisa subtrair
    lea rcx, [rdi * 2]      ; rcx = 2*numLimbs
    mov rax, [rbx + rcx*8]  ; rax = t[2*numLimbs]
    test rax, rax
    jnz .do_sub             ; Se carry != 0, subtrai
    
    ; Compara result com n (de trás para frente)
    mov r9, rdi
    dec r9                  ; r9 = numLimbs - 1
    
.cmp_loop:
    test r9, r9
    js .skip_sub            ; Se r9 < 0, são iguais -> skip (CIOS garante < n)
    
    mov rax, [r12 + r9*8]   ; result[j]
    mov rcx, [r15 + r9*8]   ; n[j]
    cmp rax, rcx
    ja .do_sub              ; result > n -> subtrai
    jb .skip_sub            ; result < n -> não subtrai
    
    dec r9
    jmp .cmp_loop
    
.do_sub:
    ; result -= n
    ; Usa contador decrescente para evitar cmp/jge que destroem CF
    mov r9, rdi             ; r9 = numLimbs (contador)
    mov r8, r12             ; r8 = &result[0]
    mov rcx, r15            ; rcx = &n[0]
    clc                     ; limpa borrow
    
.sub_loop:
    mov rax, [r8]           ; result[j]
    sbb rax, [rcx]          ; result[j] - n[j] - borrow
    mov [r8], rax
    
    lea r8, [r8 + 8]        ; r8 += 8 (não afeta flags)
    lea rcx, [rcx + 8]      ; rcx += 8 (não afeta flags)
    dec r9                  ; dec não afeta CF!
    jnz .sub_loop
    
.skip_sub:
    ; ========================================================================
    ; EPÍLOGO
    ; ========================================================================
    pop rax                 ; recupera t_size
    add rsp, rax            ; libera t[]
    
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    
    ret
