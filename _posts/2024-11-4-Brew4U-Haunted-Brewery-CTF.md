---
layout: post
title: Brew4U Haunted Brewery CTF
comments: true
categories: [Web, Writeups, HauntedBreweryCTF]
---

Este es el segundo writeup que subo del [Haunted Brewery CTF 2024](https://ctftime.org/ctf/1191/), donde logramos un puesto 20, dejando buenas sensaciones con el progreso del equipo.

![Image]({{ site.baseurl }}/images/posts/haunted-brewery-2024.png)

# Reconocimientpo

En este reto se nos presenta una página donde podemos insertar texto:

![Image]({{ site.baseurl }}/images/posts/2024-11-04-Brew4U-Haunted-Brewery-CTF-2.png)

Si investigamos con *WhatWeb*, veremos que el servidor web es *flask*, por lo que tendría sentido probar un *SSTI* (Server-Side Template Injection):

![Image]({{ site.baseurl }}/images/posts/2024-11-04-Brew4U-Haunted-Brewery-CTF-1.png)

Si enviamos dicha cadena, efectivamente recibimos un error:

![Image]({{ site.baseurl }}/images/posts/2024-11-04-Brew4U-Haunted-Brewery-CTF-3.png)

De forma, que con un input como el siguiente, se nos dará la flag:

```
\{\{ self._TemplateReference\_\_context.cycler.\_\_init\_\_.\_\_globals\_\_.os.popen('cat flag.txt').read() \}\}
```

Eso sería todo, si te ha gustado, échale un ojo a mi otro [writeup de web]({% post_url 2024-11-04-Anti-Spirit-FCaptcha-Haunted-Brewery-CTF %}).