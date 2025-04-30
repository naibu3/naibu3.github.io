---
layout: post
title: He aprobado la eJPT
comments: true
categories: [Certs, eJPT]
---

Como dice el título, finalmente lo he conseguido, he aprobado la certificación **Junior Penetration Tester v2** de [INE Security](https://security.ine.com/certifications/ejpt-certification/). Uno de mis primeros objetivos en la ciberseguridad.

<br>
![Image]({{ site.baseurl }}/images/posts/eJPT.png){:width="100px"}
<br>

# Mi experiencia

Tras darle un repaso al curso de *Penetration Testing Student* en la página de INE, y posponer la fecha del examen durante casi un mes, al fin tenía dos días libres para enfrentarme a la certificación.

## WINSERVER-2 y Ubuntu

Empecé nervioso, abrí la máquina kali que te da acceso al laboratorio. Escanée la red en busca de las máquinas visibles en la DMZ sin mucho problema y empecé con la primera. En una hora había encontrado un *ftp* mal configurado y había entrado subiendo una *reverse shell*, ya estaba confíado. En la hora siguiente saqué la segunda, un drupal sobre el que había muchísimas preguntas del tipo test.

## El apagón

Ya con dos máquinas *rooteadas*, me fui a la universidad, ya que tenía una exposición. De camino me extrañó que los semáforos estaban apagados, y al llegar me dieron la noticia: la península estaba sin electricidad. Un poco nervioso por saber cuándo volvería pasé la tarde, y ya al día siguiente, tras volver la luz, escribí a soporte. Cabe destacar que fueron súper educados, y me añadieron 24 horas de cortesía

## WINSERVER-1 y 3

Con las mismas horas con las que empecé fui a por las últimas dos máquinas accesibles de la DMZ (había una máquina linux sin puertos abiertos). La tercerá cayó fácil, dándome la puerta de entrada a la red interna. Antes de pivotar quería tener controlada toda la DMZ. No sabía el dolor que iba a ser auditar el *wordpress*. Tras unas dos horas y media por fin tenía privilegios de administrador en el *WINSERVER-1*.

## Pivoting

Sólo me separaba una tabla de enrutado de terminar mi certificación. Al comienzo es verdad que estaba un poco perdido, pero con un *autorute* y un poco de escaneo encontré los tres hosts de la red interna. Sólo uno de ellos era explotable, aunque tardé en averiguarlo debido a la lentitud de los escaneos.

Tras toda una tarde dandome cabezazos, probé a conectarme por *RDP* y por alguna mala configuración entré como root. Terminando así el examen y certificandome como *pentester junior*.

<br>
![Image]({{ site.baseurl }}/images/posts/eJPT_cert.png){:width="500px"}
<br>

# Opiniones

La verdad que es una certificación muy divertida, y quitando la parte del pivoting, tiene un laboratorio que funciona de lujo. Yo tenía cierta base, pero cualquiera puede hacer el curso y persentarse sin problema.

En definitiva, muy recomendable, y si estás empezando en el pentesting aún más.

# Recomendaciones

Si te vas a presentar, te dejo algunos tips que me vinieron bien durante el examen. En su día también leí las infinitas páginas de blogs de personas dando sus propias opiniones, por ello voy a intentar poner algunas que no ví.

## Enumera

Puede que me contradiga, pero la clave de este examen es responder a las preguntas. Si no te lo piden no tienes que rootear una máquina, eso sí, en ocasiones buscar lo que te piden será más difícil de buscar, incluso si eres root. Una vez estés dentro, no te vayas sin sacar todos lo que te parezca relevante, incluso nombres de usuarios, hashes (tanto de bases de datos como del `/etc/shadow`) y archivos.

## Haz fuerza bruta

Yo no lo creía, pero muchas veces se puede entrar por fuerza bruta con *hydra* o a veces sin contraseña. Si tienes un usuario intenta sacarle la contraseña a la fuerza, o entrar por *mysql* o *RDP*.

## Apunta todo

Si no quieres tener que explotar las máquinas varias veces utiliza *cherrytree* o, como en mi caso, *obsidian*. Si tienes credenciales te ahorrarás mucho tiempo a volver a comprobar cosas.

Si estás pensando en presentarte, **MUCHA SUERTE!**

<br>