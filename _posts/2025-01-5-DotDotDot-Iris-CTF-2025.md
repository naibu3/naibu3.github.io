---
layout: post
title: DotDotDot Iris CTF 2025
comments: true
categories: [RF, Writeups, IrisCTF]
---

Llevaba tiempo siin subir ningún post, y qué mejor forma de empezar el año que con un writeup del [Iris CTF](https://ctftime.org/event/2503/). Este es un ejercicio de una categoría que se ve extremadamente poco, y dado que tenía poco tiempo, es el único que pude resolver.

<br>

![Image]({{ site.baseurl }}/images/posts/irisctf-logo.png){:width="400px"}

<br>

# Overview

La descripción del reto nos dice lo siguiente:

	I picked up this transmission, but it's way too noisy to make any sense of it. Can you give it a shot?

Además se nos da un archivo con extensión `.iq`.
<br>

# Explotación

Lo primero sería investigar qué extensión es `.iq`, que resulta ser un archivo de señal. Para abrirlo podemos utilizar un programa como *inspectrum*, que nos permitirá ver la propia señal. Con un pequño ajuste podemos ver que la señal tiene una forma que recuerda al código morse:

<br>

![Image]({{ site.baseurl }}/images/posts/2025-01-05-inspectrum.png){:width="800px"}

<br>

Descifrándolo como morse obtenemos la flag: `irisctf{n01s3_g0t_n0th1ng_0n_my_m0rse}`.

<br>