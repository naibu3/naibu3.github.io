---
layout: post
title: Biscuits BITSCTF2025
comments: true
categories: [Pwn, Writeups, BITSCTF2025]
---

En este último ctf sólo había dos ejercicios de PWN, además bastante sencillito, así que he decidido subir writeup de los dos.

<br>
![Image]({{ site.baseurl }}/images/posts/BITSCTF.png){:width="150px"}
<br>

# Overview

El enunciado dice lo siguiente:

    Momma, can I have cookie..?

    No....

Además incluye un binario `main`.

# Reconocimiento

Lo primero será analizar el binario:

```bash
❯ file main
main: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=102ac972af333cb069ddd21a54364dbbe2a0d9ed, for GNU/Linux 3.2.0, not stripped
❯ checksec --file=main
[*] '/home/kali/Downloads/biscuits/main'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

Vemos que es de 64 bits y que tiene todas las protecciones activas. Si lo descompilamos con *ghidra* veremos un código como el siguiente:

```c
undefined8 main(void)
{
  int rand_n;
  time_t time;
  size_t end_of_input;
  FILE *__stream;
  long in_FS_OFFSET;
  int i;
  char input [112];
  char cookie [104];
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  time = ::time((time_t *)0x0);
  srand((uint)time);
  puts("Give me the cookie I want a 100 times in a row and I\'ll give you the flag!");
  fflush(stdout);
  for (i = 0; i < 100; i = i + 1) {
    rand_n = rand();
    strcpy(cookie,*(char **)(cookies + (long)(rand_n % 100) * 8));
    printf("Guess the cookie: ");
    fflush(stdout);
    fgets(input,100,stdin);
    end_of_input = strcspn(input,"\n");
    input[end_of_input] = '\0';
    rand_n = strcmp(input,cookie);
    if (rand_n != 0) {
      printf("Wrong. The cookie I wanted was: %s\n",cookie);
                    /* WARNING: Subroutine does not return */
      exit(0);
    }
    printf("Correct! The cookie was: %s\n",cookie);
    fflush(stdout);
  }
  printf("Congrats!\nFlag: ");
  fflush(stdout);
  __stream = fopen("flag.txt","r");
  if (__stream == (FILE *)0x0) {
    perror("Failed to open flag file");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  while( true ) {
    rand_n = fgetc(__stream);
    if ((char)rand_n == -1) break;
    putchar((int)(char)rand_n);
  }
  putchar(10);
  fclose(__stream);
  fflush(stdout);
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}

                            cookies                                         XREF[3]:     Entry Point(*), main:001023e9(*), 
                                                                                          main:001023f0(*)  
        00105020 08 30 10        undefine
                 00 00 00 
                 00 00 17 
           00105020 08              undefined108h                     [0]           ?  ->  00103008     XREF[3]:     Entry Point(*), main:001023e9(*), 
                                                                                                                     main:001023f0(*)  
           00105021 30              undefined130h                     [1]
           00105022 10              undefined110h                     [2]
           00105023 00              undefined100h                     [3]
           00105024 00              undefined100h                     [4]
           00105025 00              undefined100h                     [5]
           00105026 00              undefined100h                     [6]
           00105027 00              undefined100h                     [7]
           00105028 17              undefined117h                     [8]           ?  ->  00103017
           00105029 30              undefined130h                     [9]
           0010502a 10              undefined110h                     [10]
           0010502b 00              undefined100h                     [11]
           0010502c 00              undefined100h                     [12]
           0010502d 00              undefined100h                     [13]
           0010502e 00              undefined100h                     [14]
           0010502f 00              undefined100h                     [15]
           00105030 24              undefined124h                     [16]          ?  ->  00103024
           [...]
           00105330 e2              undefined1E2h                     [784]         ?  ->  001035e2
           00105331 35              undefined135h                     [785]
           00105332 10              undefined110h                     [786]
           00105333 00              undefined100h                     [787]
           00105334 00              undefined100h                     [788]
           00105335 00              undefined100h                     [789]
           00105336 00              undefined100h                     [790]
           00105337 00              undefined100h                     [791]
           00105338 fe              undefined1FEh                     [792]         ?  ->  001035fe
           00105339 35              undefined135h                     [793]
           0010533a 10              undefined110h                     [794]
           0010533b 00              undefined100h                     [795]
           0010533c 00              undefined100h                     [796]
           0010533d 00              undefined100h                     [797]
           0010533e 00              undefined100h                     [798]
           0010533f 00              undefined100h
```

Vemos que el programa pide que vayas introduciendo distintas cadenas que toma aleatroiamente de un array. Si vemos el contenido de las direcciones podemos sacar los valores del array:

```
        00103008 43 68 6f        ds         "Chocolate Chip"
                 63 6f 6c 
                 61 74 65 
        00103017 53 75 67        ds         "Sugar Cookie"
                 61 72 20 
                 43 6f 6f 
        00103024 4f 61 74        ds         "Oatmeal Raisin"
                 6d 65 61 
                 6c 20 52 
        00103033 50 65 61        ds         "Peanut Butter"
                 6e 75 74 
                 20 42 75 
        00103041 53 6e 69        ds         "Snickerdoodle"
                 63 6b 65 
                 72 64 6f 
        0010304f 53 68 6f        ds         "Shortbread"
                 72 74 62 
                 72 65 61 
        0010305a 47 69 6e        ds         "Gingerbread"
                 67 65 72 
                 62 72 65 
        00103066 4d 61 63        ds         "Macaron"
                 61 72 6f 
                 6e 00
```

La generación aleatoria se hace mediante la semilla `srand((uint)time);` y se generan números con `rand_n = rand();`.

# Explotación

Dado que se utiliza como semilla la hora en la que se ejecuta el binario. Podríamos capturar ese istante y utilizarlo para generar números idénticos y así obtener la flag. Para ello lo haremos mediante un script en *python3* y *pwntools*:

```python
#!/usr/bin/env python3
from pwn import *
import ctypes

if len(sys.argv) == 1:
    p = remote('20.244.40.210', 6000)
else:
    p = process('./main')

libc = ctypes.CDLL("libc.so.6")

seed = libc.time(0)
libc.srand(seed)

data = p.recvline().decode().rstrip()
print(data)

table = [0x00103008, 0x00103017, 0x00103024, 0x00103033, 0x00103041,
    0x0010304f, 0x0010305a, 0x00103066, 0x0010306e, 0x00103077, 0x00103080,
    0x0010308e, 0x001030ac, 0x001030c2, 0x001030cd, 0x001030df, 0x001030ee,
    0x001030fc, 0x0010310e, 0x0010311d, 0x00103134, 0x00103144, 0x00103153,
    0x00103160, 0x00103170, 0x00103182, 0x00103192, 0x001031a1, 0x001031b3,
    0x001031c8, 0x001031dc, 0x001031ec, 0x00103204, 0x00103216, 0x0010322a,
    0x0010323f, 0x00103250, 0x00103260, 0x0010326e, 0x0010327c, 0x0010328a,
    0x0010329b, 0x001032a9, 0x001032bb, 0x001032c7, 0x001032d1, 0x001032db,
    0x001032e6, 0x001032f4, 0x001032fe, 0x00103307, 0x00103310, 0x0010331d,
    0x00103328, 0x00103334, 0x00103341, 0x0010334d, 0x00103356, 0x0010335f,
    0x00103368, 0x00103380, 0x0010338a, 0x00103392, 0x00103398, 0x001033a7,
    0x001033b7, 0x001033c6, 0x001033d4, 0x001033e6, 0x001033ed, 0x001033ff,
    0x0010340f, 0x0010341d, 0x00103428, 0x00103435, 0x0010343f, 0x0010344e,
    0x0010345f, 0x00103471, 0x0010347d, 0x00103489, 0x00103492, 0x001034a1,
    0x001034b1, 0x001034c5, 0x001034d4, 0x001034eb, 0x001034fb, 0x00103513,
    0x00103528, 0x0010353d, 0x00103557, 0x0010356d, 0x00103582, 0x00103591,
    0x001035a3, 0x001035b3, 0x001035ca, 0x001035e2, 0x001035fe]

with open('main', 'rb') as f:
    bin_data = f.read()

for i in range(100):
    r = libc.rand()
    offset = table[r % 100] - 0x00100000
    end = bin_data.find(b'\x00', offset)
    cookie = bin_data[offset:end].decode()

    data = p.recvuntil(b': ').decode()
    print(data + cookie)
    p.sendline(cookie.encode())
    data = p.recvline().decode().rstrip()
    print(data)

for _ in range(2):
    data = p.recvline().decode().rstrip()
    print(data)
```

Ejecutamos y tendríamos la flag! Si te ha gustado, échale un vistazo a mis otros writeups y no dudes en seguirme en redes sociales.

Reconocimiento al [writeup original](https://yocchin.hatenablog.com/entry/2025/02/10/081405) (en Japonés).

<br>