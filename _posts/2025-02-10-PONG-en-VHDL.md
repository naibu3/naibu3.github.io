---
layout: post
title: PONG en VHDL
comments: true
categories: [Proyectos]
---

Este es un proyecto que realicé como trabajo para la asignatura de Sistemas Reconfigurables. Se trata de una versiñon sencilla del clásico PONG para la **Basys 3**. Esta es una placa de desarrollo *FPGA* que se programa de forma muy sencilla con la suite *Vivado*.

<br>
![Image]({{ site.baseurl }}/images/posts/pong/pantalla_titulo.jpg){:width="400px"}
<br>

Todos los archivos necesarios se encuentran en mi [Github](https://github.com/naibu3/PONG). Además de un manual con información detallada de los módulos.

<br>

---

<br>

# Materiales

Para este proyecto necesitaremos:

1. Una **Basys 3**, una placa FPGA basada en la Xilinx Artix-7.
2. Para el desarrollo y la programación de la placa utilizaremos la suite de **Vivado** en Windows.
3. Un módulo de **buzzer pasivo**.
4. **Monitor con entrada VGA** (y su respectivo cable). En este caso, utilizaremos un monitor de 640x480 px a 60 Hz.

El montaje es tan simple como conectar el cable VGA a la placa ya al monitor, y los pines del buzzer a 3v3, GND y al puerto JB4 de la placa.

<br>
![Image]({{ site.baseurl }}/images/posts/pong/montaje.jpg){:width="300px"}
<br>


# Programación

Cloneremos el repositorio y añadiremos los archivos a un nuevo proyecto. No olvides añadir el fichero de constantes y asignar `TopModule.vhd` como *Top*. Una vez listo, generamos el *Bitstream* y programamos la placa.

# Cómo jugar

Antes de empezar, podemos ajustar la dificultad con los switches 14 y 15:

<br>
![Image]({{ site.baseurl }}/images/posts/pong/switches.jpg){:height="200px"}
<div style="display: flex; justify-content: center; align-items: center;">
    <img src="/images/posts/pong/facil.jpg" style="height:200px;">
    <img src="/images/posts/pong/dificil.jpg" style="height:200px;">
</div>
<br>

Para iniciar el juego debemos pulsar en el botón central:

<br>
![Image]({{ site.baseurl }}/images/posts/pong/boton_centro.jpg){:height="200px"}
<br>

Y nos moveremos con los laterales:

<br>
<div style="display: flex; justify-content: center; align-items: center;">
    <img src="/images/posts/pong/boton_izuierda_derecha.jpg" style="height:200px;">
    <img src="/images/posts/pong/juego.jpg" style="height:200px;">
</div>
<br>

Y eso es todo! Si te ha gustado el proyecto, no dudes en seguirme y leer el resto de posts!