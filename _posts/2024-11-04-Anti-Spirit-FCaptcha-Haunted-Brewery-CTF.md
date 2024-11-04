---
layout: post
title: Anti Spirit FCaptcha Haunted Brewery CTF
comments: true
categories: [Web, Writeups, HauntedBreweryCTF]
---

Este es el tercer y último writeup que subo del [Haunted Brewery CTF 2024](https://ctftime.org/ctf/1191/), donde logramos un puesto 20, dejando buenas sensaciones con el progreso del equipo.

![Image]({{ site.baseurl }}/images/posts/haunted-brewery-2024.png)

# Reconocimientpo

En este caso, tenemos una web con un captcha *troll* que al clickarlo nos dirá que no somos un humano. Para saltarlo, vale con borrar el código javascript de la página. Una vez hecho esto, recibiremos como respuesta del servidor una imagen en base64.

Para decodificarla, podemos utilizar *python*:

```python
import base64

# Leer la cadena base64 desde un archivo
with open("image.png", "r") as file:
    data_base64 = file.read().strip()

# Opcional: Elimina el principio de la cadena ('data:image/png;base64,🚬SMOKEYOUUU🚭')
prefix = "data:image/png;base64,🚬SMOKEYOUUU🚭"
if data_base64.startswith(prefix):
    data_base64 = data_base64[len(prefix):]

# Decodificar y guardar la imagen
with open("flag.png", "wb") as image_file:
    image_file.write(base64.b64decode(data_base64))
```

Ya solo tenemos que abrir la imagen:

![Image]({{ site.baseurl }}/images/posts/2024-11-04-Anti-Spirit-FCaptcha-Haunted-Brewery-CTF.png)

Eso sería todo, si te ha gustado, échale un ojo a mi otro [writeup de web]({% post_url 2024-11-04-Brew4U-Haunted-Brewery-CTF %}).