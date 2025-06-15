---
layout: post
title: RPS PicoGym
comments: true
categories: [Pwn, Writeups, PicoCTF]
---

En este post estaremos resolviendo un reto del [PicoGym](https://play.picoctf.org/practice/challenge/490?category=6&page=1&retired=0) y su segunda parte. En este caso se trata de un reto sencillito para calentar.

<br>
![Image]({{ site.baseurl }}/images/posts/picoGym/pico_logo.png){:width="200px"}

# Reconocimiento

   > Here's a program that plays rock, paper, scissors against you. I hear something good happens if you win 5 times in a row.

En este caso se nos da un código en C con un juego simple de *piedra-papel-tijera*. Anallizándolo veremos que la comprobación para determinar si el jugador gana o pierde la ronda no hace lo que debería:

```c
  if (strstr(player_turn, loses[computer_turn])) {
    puts("You win! Play again?");
    return true;
  } else {
    puts("Seems like you didn't win this time. Play again?");
    return false;
  }
```

La función `strstr` solo comprueba si la primera cadena se encuentra dentro de la segunda, por tanto si en las 5 rondas respondemos algo como `rockpaperscissors` ganaremos siempre.

## Explotación

Como hemos dicho, bastará con enviar la misma cadena 5 veces:

```bash
Please make your selection (rock/paper/scissors):
rockpaperscissors
rockpaperscissors
You played: rockpaperscissors
The computer played: scissors
You win! Play again?
Type '1' to play a game
Type '2' to exit the program
1
1

[...]

Please make your selection (rock/paper/scissors):
rockpaperscissors
rockpaperscissors
You played: rockpaperscissors
The computer played: rock
You win! Play again?
Type '1' to play a game
Type '2' to exit the program
1
1


Please make your selection (rock/paper/scissors):
rockpaperscissors
rockpaperscissors
You played: rockpaperscissors
The computer played: rock
You win! Play again?
Congrats, here's the flag!
picoCTF{<REDACTED>}
```

<br>