---
layout: post
title: Wordle 2025
comments: true
categories: [Pwn, Writeups, HFCTF2025]
---

Al igual que el año pasado, he participado en el [Hackademics Forum CTF](hackademics-forum.com), aunque como autor de los retos de categoría Pwn. Dado que era un CTF de un evento en el que asisten gran cantidad de público universitario con un nivel no tan alto, estos son retos sencillitos para que le vayan cogiendo cariño a la categoría.

<br>
![Image]({{ site.baseurl }}/images/posts/HFCTF.png){:width="250px"}
<br>

# Overview

Este primer reto era en mi opinión el más fácil, aunque fue superado en solves por [feedback]({% post_url 2025-04-6-Feedback-HFCTF %}). También se debatió si debería entrar en la categoría de Pwn, ya que aprovecharemos que podemos controlar la semilla de PRNG y predecir las respuestas.

# Reconocimiento

Si decompilamos el binario que se nos proporciona, veremos las siguientes fucniones:

```c
int contar_caracteres(char *str) {
    int count = 0;
    while (*str) {
        count++;
        str++;
    }
    return count;
}

void banner() {
    [...]
}    

void flag() {
    FILE *file = fopen("flag", "r"); // Abrir el archivo en modo lectura
    if (file == NULL) {
        printf("No se pudo abrir el archivo flag\n"); flush_buffers();
        return;
    }

    char ch;
    while ((ch = fgetc(file)) != EOF) { // Leer carácter por carácter
        putchar(ch); flush_buffers();
    }

    fclose(file); // Cerrar el archivo
    printf("\n"); flush_buffers();
}

int main() {

    banner();

    char nombre[100];
    char intento[100];

    const char *palabras[TOTAL_PALABRAS] = {
        "mezquita", "califato", "medina", "alcazar", "patios", "flamenco", "guitarra", "feria", "romeria", "cruces",
        "juderia", "mayo", "puente_romano", "guadalquivir", "calahorra", "molinos", "calleja", "caballo", "flores", "gitana",
        "montilla", "moriles", "vino", "aceite", "olivo", "sierra", "subbetica", "hornazo", "salmorejo", "flamenquin",
        "rabo", "naranjos", "alminar", "ermita", "sierra", "UCO", "fuensanta", "cordobes", "cordobesa", "torero",
        "museo", "medina_azahara", "sombra", "azulejos", "calesa", "cogolludo", "arruzafa", "albolafia", "sotos", "san_basilio",
        "catedral", "cristianos", "musulmanes", "mudejar", "barroco", "renacimiento", "cofradia", "semana_santa", "paso", "costalero",
        "saeta", "campanas", "caballerizas", "capilla", "naibu3", "fernandinas", "rejas", "gruta", "baños_arabes", "pozoblanco",
        "priego", "lucena", "montoro", "cabra", "zuheros", "baena", "villafranca", "pedroches", "encina", "parque_natural",
        "califa", "abderraman", "alhakem", "omeya", "azahara", "carmona", "picon", "acebuchal", "madinat", "arruzafilla",
        "portichuelo", "triana", "fuensantilla", "alcolea", "almodovar", "flag", "Hackademics", "guadalbarbo", "Aula_Ciberseguridad_y_Redes", "torrox"
    };
    

    // Pedir nombre al usuario
    printf("\nIntroduce un nombre de usuario: "); flush_buffers();
    fgets(nombre, sizeof(nombre), stdin); flush_buffers();
    // Eliminar el salto de línea si lo hay
    nombre[strcspn(nombre, "\n")] = '\0';

    int caracteres = contar_caracteres(nombre);
    printf("\n[DEBUG] Numero de caracteres: %d\n", caracteres); flush_buffers();

    srand(caracteres);  // Usa el número de caracteres como semilla

    printf("\nAdivina las 100 palabras secretas.\n"); flush_buffers();

    const char *palabra_secreta;

    // Bucle de intentos
    for (int i = 0; i < 100; i++) {
        palabra_secreta = palabras[rand() % TOTAL_PALABRAS];  // Nueva palabra en cada intento

        //printf(palabra_secreta);

        printf("Palabra %d: ", i + 1); flush_buffers();
        fgets(intento, sizeof(intento), stdin); flush_buffers();
        intento[strcspn(intento, "\n")] = '\0'; // Eliminar salto de línea

        if (strcmp(intento, palabra_secreta) == 0) {
            printf("\nCorrecto! Has adivinado la palabra.\n"); flush_buffers();
            continue;
        } else {
            printf("\nIncorrecto. Vete a jugar algo mas facil!\n"); flush_buffers();
            exit(-1);
        }
    }

    printf("Imposible que hayas ganado, seguro que hiciste trampas! Xb\n"); flush_buffers();

    flag();

    exit(0);
}
```

Vemos que el juego nos pedirá que adivinemos 100 palabras elegidas aleatoriamente de una lista. Por suerte, vemos que el valor de la *seed* es la longitud del número de letras del nombre de usuario. Por tanto podemos predecir el orden de las palabras.

```c
 int caracteres = contar_caracteres(nombre);
    printf("\n[DEBUG] Numero de caracteres: %d\n", caracteres); flush_buffers();

    srand(caracteres);  // Usa el número de caracteres como semilla
```

# Explotación

Al ser cien palabras lo mejor es lanzar un script en python:

```python
#!/usr/bin/env python3
from pwn import *
import ctypes
import sys

libc = ctypes.CDLL("libc.so.6")

if len(sys.argv) == 1:
    p = remote('localhost', 33334)
else:
    p = process('./main')

libc.srand(6)

# RECEIVE HEADER
for i in range(0, 18):
    data = p.recvline().decode().rstrip()
    print(data)

data = p.recvuntil(b"usuario:")
print(data)
p.sendline("naibu3")

data = p.recvline()
print(data)
data = p.recvline()
print(data)
data = p.recvline()
print(data)
data = p.recvline()
print(data)


table = ["mezquita", "califato", "medina", "alcazar", "patios", "flamenco", "guitarra", "feria", "romeria", "cruces",
        "juderia", "mayo", "puente_romano", "guadalquivir", "calahorra", "molinos", "calleja", "caballo", "flores", "gitana",
        "montilla", "moriles", "vino", "aceite", "olivo", "sierra", "subbetica", "hornazo", "salmorejo", "flamenquin",
        "rabo", "naranjos", "alminar", "ermita", "sierra", "UCO", "fuensanta", "cordobes", "cordobesa", "torero",
        "museo", "medina_azahara", "sombra", "azulejos", "calesa", "cogolludo", "arruzafa", "albolafia", "sotos", "san_basilio",
        "catedral", "cristianos", "musulmanes", "mudejar", "barroco", "renacimiento", "cofradia", "semana_santa", "paso", "costalero",
        "saeta", "campanas", "caballerizas", "capilla", "naibu3", "fernandinas", "rejas", "gruta", "baños_arabes", "pozoblanco",
        "priego", "lucena", "montoro", "cabra", "zuheros", "baena", "villafranca", "pedroches", "encina", "parque_natural",
        "califa", "abderraman", "alhakem", "omeya", "azahara", "carmona", "picon", "acebuchal", "madinat", "arruzafilla",
        "portichuelo", "triana", "fuensantilla", "alcolea", "almodovar", "flag", "Hackademics", "guadalbarbo", "Aula_Ciberseguridad_y_Redes", "torrox"] # Words

for i in range(100):
    r = libc.rand()
    word = table[r % 100]
    log.info(word)

    data = p.recvuntil(b': ').decode()
    print(data + word)
    p.sendline(word.encode())
    response = p.recvline().decode().rstrip()
    print(response)

for _ in range(3):
    data = p.recvline().decode().rstrip()
    print(data)

```