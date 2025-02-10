---
layout: post
title: Juego de la Vida en Scheme
comments: true
categories: [Programación]
---

Esta mañana he finiquitado una de las últimas asignaturas que me quedan de carrera, *Programación Declarativa*. Lo que me quedaba era exponer un pequeño proyecto que teníamos que hacer como conclusión. Como no quería complicarme, me decanté por una implementación del [Juego de la Vida de Conway](https://es.wikipedia.org/wiki/Juego_de_la_vida).

Antes de empezar, dejaros como curiosidad que si poneis `juego de la vida de conway` en google, veréis un pequeño *easter egg*.

<br>

![Image]({{ site.baseurl }}/images/posts/trabajo-PD/titulo.png){:width="400px"}

<br>

# Introducción

La idea del trabajo era profundizar en el desarrollo en el lenguaje Scheme y el uso de librerías gráficas. Por ello, la aplicación implementa el Juego de la Vida, permitiendo:

- Modificar las reglas del Juego.
- Generar tableros vacíos/aleatorios (con diferente nivel de entropía)
- Importar/exportar tableros a ficheros
- Poder modificar el tablero en tiempo real
- Detener y reanudar el juego
- Ajustar la velocidad del juego

Por suerte, el paradigma **declarativo** es muy versátil para este programa en concreto. De forma que tendremos un código bastante corto y entendible.

## El Juego de la Vida

Aunque no pretendo profundizar en qué es el ***Juego de la Vida*** de Conway, debemos explicarlo brevemente. Aunque se llame "*Juego*", no es un juego como tal, sino una simulación que dado un estado inicial de un conjunto de celdas en una cuadrícula, evoluciona de forma "*orgánica*" hacia estados más complejos. A este tipo de sistemas se les conoce como [Autómatas celulares](https://es.wikipedia.org/wiki/Aut%C3%B3mata_celular).

En concreto, el Juego de la Vida, define dos estados para cada celda:

- Viva (negro)
- Blanca (muerta)

Y en cada iteración, las casillas evolucionan en base a las siguientes reglas:

- **Supervivencia**: Una célula viva permanece viva si tiene **exactamente 2 o 3 vecinos vivos**.
- **Muerte por soledad**: Una célula viva muere si tiene **menos de 2 vecinos vivos**.
- **Muerte por sobrepoblación**: Una célula viva muere si tiene **más de 3 vecinos vivos**.
- **Nacimiento**: Una célula muerta se convierte en una célula viva si tiene **exactamente 3 vecinos vivos**.

Con tan sólo estas reglas y una entrada inicial, el sistema evoluciona hacia estados que pueden alcanzar un nivel de complejidad altísimo.

# Implementación

El código completo se puede encontrar en [mi perfil de Github](https://github.com/naibu3). Aunque vamos a ver lo más importante. En cuanto a módulos,
tenemos por una parte la lógica del juego y por otro, la interfaz gráfica. Para llamar al programa lo hacemos desde `main.rkt`.

## Lógica del juego

Gracias a la modularidad y la capacidad de recursión que ofrece el lenguaje, el código es bastante corto y simple. Destaca sobre todo la función que calcula el siguiente estado del tablero, que es la encargada de englobar al resto:

<br>

![Image]({{ site.baseurl }}/images/posts/trabajo-PD/update-grid.png){:width="800px"}

<br>

Esta función toma una lista unidimensional de celdas y las dimensiones del tablero, y una regla que se aplicará a dicho tablero. De esta forma, podemos cambiar en cualquier momento las reglas que aplican al juego o incluso la topología del tablero.

Sin embargo, para el trabajo, implementé la siguiente función:

<br>

![Image]({{ site.baseurl }}/images/posts/trabajo-PD/life-rule.png){:width="800px"}

<br>

## Interfaz gráfica

Para la interfaz gráfica utilicé `racket/gui`, que a pesar de no ofrecer un nivel demasiado elevado de personalización, permite crear una interfaz más que funcional para el programa. El funcionamiento es similar al de otras librerías similares en otros lenguajes. El diagrama de ventanas es el siguiente:

<br>

![Image]({{ site.baseurl }}/images/posts/trabajo-PD/life-rule.png){:width="800px"}

<br>


Os dejo un ejemplo del menú principal:

<br>

![Image]({{ site.baseurl }}/images/posts/trabajo-PD/layout.png){:width="400px"}

<br>

Como he dicho, podeís ver el código completo en mi [GitHub](https://github.com/naibu3).

<br>