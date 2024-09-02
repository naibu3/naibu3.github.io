---
layout: post
title: Key Cyber Space '24
comments: true
categories: [Reversing, Writeups, CyberSpace]
---

Este es un reto del **Cyber Space '24** y pese a ser un reto de la categoría de *begginer-reversing*, me ha parecido interesante de compartirlo aquí.

# Reconocimiento

Se nos da un archivo *key*, binario de 64 bits. Con alguna herramienta como *ghidra* descompilamos y vemos el siguiente código:

```c
undefined8 main(void)
{
  size_t inputLen;
  long in_FS_OFFSET;
  uint i;
  int aiStack_138 [32];
  int local_b8 [4];
  undefined4 local_a8;
  [...]
  undefined4 local_3c;
  char input [40];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_b8[0] = 0x43;
  local_b8[1] = 0xa4;
  local_b8[2] = 0x41;
  local_b8[3] = 0xae;
  local_a8 = 0x42; local_a4 = 0xfc;
  local_a0 = 0x73; local_9c = 0xb0;
  local_98 = 0x6f; local_94 = 0x72;
  local_90 = 0x5e; local_8c = 0xa8;
  local_88 = 0x65; local_84 = 0xf2;
  local_80 = 0x51; local_7c = 0xce;
  local_78 = 0x20; local_74 = 0xbc;
  local_70 = 0x60; local_6c = 0xa4;
  local_68 = 0x6d; local_64 = 0x46;
  local_60 = 0x21; local_5c = 0x40;
  local_58 = 0x20; local_54 = 0x5a;
  local_50 = 0x2c; local_4c = 0x52;
  local_48 = 0x2d; local_44 = 0x5e;
  local_40 = 0x2d; local_3c = 0xc4;

  printf("Enter the key: ");
  __isoc99_scanf(&DAT_00102014,input);

  inputLen = strlen(input);
  if ((int)inputLen == 32) {

    for (i = 0; ((int)i < 32 &&
                
            (aiStack_138[(int)i] = ((int)input[(int)i] ^ i) * ((int)i % 2 + 1),
            aiStack_138[(int)i] == local_b8[(int)i]))

        ; i = i + 1) {

      if (i == 0x1f) {
        printf("Success!");
      }
    }
  }
  else {

    printf("Denied Access");
  }
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return 0;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

Vemos que se nos pide introducir una contraseña, que debe tener 32 B de longitud, en caso contrario nos dirá `Denied Access`.

Además para cada byte introducido, realizará una operación que se va guardando en `aiStack_138` y se va comprobando con los valores de `local_a8` a `local_3c`.

## Operativa

Para cada carácter que se ingresa, se realiza un XOR entre ese carácter y el índice de su posición *i*, después se multiplica el resultado por `((int)i % 2 + 1)`, el resultado se guarda en `aiStack_138`. A continuación, se compara el valor con los almacenados en `local_a8` a `local_3c`.

## Ingeniería inversa

La operativa que se está aplicando por byte es:

    resultado=(input[i]⊕i)×(i%2+1)

Al revertir dicha expresión surgen dos casos:

- Cuando *i* es **par**, `i % 2 == 0`:

La fórmula se simplifica a `resultado = input[i] ^ i`, al revertirla se queda en `input[i] = resultado ^ i`.

- Cuando *i* es **impar**, `i % 2 == 1`:

La fórmula es `resultado = (input[i] ^ i) * 2`, y al revertirla queda `input[i] = (resultado / 2) ^ i`.

# Explotación

Sabiendo esto sólo queda escribir un código en python que nos haga el cálculo.

```python
#! /bin/python3

def solver():

    expected_values = [
            0x43, 0xa4, 0x41, 0xae, 0x42, 0xfc, 0x73, 0xb0,
            0x6f, 0x72, 0x5e, 0xa8, 0x65, 0xf2, 0x51, 0xce,
            0x20, 0xbc, 0x60, 0xa4, 0x6d, 0x46, 0x21, 0x40,
            0x20, 0x5a, 0x2c, 0x52, 0x2d, 0x5e, 0x2d, 0xc4
        ]


    key = [''] * 32

    for i in range(32):
        if i % 2 == 0:  # i es par
            key[i] = chr(expected_values[i] ^ i)

        else:  # i es impar
            key[i] = chr((expected_values[i] // 2) ^ i)


    return ''.join(key)


if __name__ == "__main__":

    print(solver())
```

Y con esto habríamos resuelto el ejercicio!
