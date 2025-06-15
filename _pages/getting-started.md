---
layout: page
title: Cómo empezar en PWN
permalink: /getting-started/
---

<br>

En su momento, me vi tratando de aprender sobre explotación de binarios ó *pwn*. Sin embargo, la realidad es que encontré que hay realmente poca información en castellano sobre el tema, y muy desorganizada. Por tanto, decidí crear este blog, como una forma de compartir mi aprendizaje para que cualquiera que venga detrás lo tenga mucho más fácil.

<br>

___

<br>

# La base

Lo primero de todo debe ser empezar por la base, y esa es la estructura de computadores (la parte más básica de la arquitectura de computadores). Para que cuando empecemos a hablar de registros, punteros de pila, y demás conceptos puedas seguir el hilo. Con unas nociones básicas sobre las distintas partes de la arquitectura de Von Neumann será suficiente.

Además, te recomendaría aprender algo de lenguage C/C++ ya que es el lenguaje en el que se escribieron la mayoría de sistemas operativos y con el que más tiene que ver ésta rama.

En general éstos conceptos los habrás aprendido si estás estudiando una carrera de informática, software ó similar.

Como recurso y apoyo durante tu aprendizaje hasta un nivel medio-alto, te recomiendo el libro [Linux Exploiting](https://0xword.com/es/libros/55-linux-exploiting.html) de David Puente Castro, editado por 0xWord. Este libro detalla de una forma muy clara las técnicas básicas de explotación de binarios y me parece el mejor recurso para adentrarse en este mundo.

<br>

![Image]({{ site.baseurl }}/images/pages/linux-exploiting.jpg){:width="50%"}

<br>

___

<br>

# Entrando en materia - BOF

Lo primero a aprender en la explotación de binarios es sobre los ***Buffer Overflows***, es casi siempre el primer paso en los ataques de PWN. Por tanto tu primera misión será familiarizarte con ellos y volverte un experto encontrándolos.

El siguiente paso será aprender sobre los ataques tipo ***ret2win***, y sobre cómo funcionan los ***format string attacks***.

Para to ello, te recomiendo ésta [lista](https://youtu.be/wa3sMSdLyHw?si=pFPah_52mHrk1Q2g) del youtuber *Crypto Cat* (aunque la lista alcanza un nivel bastante alto al final), y el primer [reto](https://ropemporium.com/challenge/ret2win.html) de *ROP Emporium*, con él puedes familiarizarte con las particularidades de las distintas arquitecturas.

También tienes la plataforma [picoCTF](https://play.picoctf.org/practice), por ahora te servirá con los retos fáciles, pero conforme progresas puedes ir resolviéndolos todos.

<br>

___

<br>

# Progresando - Shellcodes

El siguiente paso lógico es meter la cabeza en el mundo de los ***shellcodes***. Al principio, ver todo el código en ensamblador es bastante desafiante, pero poco a poco te sentirás muy cómodo entre tantos *mov* y *pop*.

<br>

___

<br>

# Cogiendo carrerilla - ROP

En este punto, toca lidiar con la protección del *bit NX*, que no nos dejará meter nuestros *shellcodes*, pero, ¡no pasa nada! Siempre podemos utilizar las instrucciones del propio binario en su contra, en esto consiste el [***ROP***]({% post_url 2024-08-15-ROP %}). Aquí te empezarás a sentir poderoso, que puedes destruir cualquier binario que se te ponga por delante.

Para ello, lo mejor es la plataforma de [ROP Emporium](https://ropemporium.com/challenge/split.html), además, en este mismo blog tenemos una serie con todos los writeups.

<br>

___

<br>

# Siguientes pasos

Ahora mismo me encuentro en este paso, ya sé sobre ensamblador, cómo puedo controlar los datos del programa y el flujo de ejecución. Lo siguente será aprender sobre la memoria dinámica y el *heap*, o incluso técnicas avanzadas de los otros tipos de ataques. Y para finalizar, lanzarse a explotar vulnerabilidades en el kernel del sistema operativo, y quién sabe, algún día encontrar tus primeras vulnerabilidades zero-day!

Ahora estoy con este libro sobre kernel, por si os interesa está en pdf:

<br>

![Image]({{ site.baseurl }}/images/pages/a-guide-to-kernel-exploitation.png){:width="50%"}

<br>