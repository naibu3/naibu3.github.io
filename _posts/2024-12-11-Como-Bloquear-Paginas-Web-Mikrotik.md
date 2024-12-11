---
layout: post
title: Como Bloquear Sitios Web con un Router MikroTik
comments: true
categories: [Redes]
---

Hoy he expuesto en clase un pequeño trabajo optativo para la asignatura de Redes de Altas Prestaciones de mi universidad. Se trataba de configurar *ACLs* en un router doméstico. Para ello, el profesor me prestó un router *Mikrotik hEX S* y un inyector PoE. Solo puedo decir que para navidades ya me he pedido un router para mí jeje.

<br>

---

# Montaje

En mi caso opté por un montaje simple, ya que nadie tiene en su propia casa una red segmentada con múltiples dispositivos de red. El esquema es el siguiente:

<br>

![Image]({{ site.baseurl }}/images/posts/trabajo-RAP/diagrama.png){:width="400px"}

<br>

Fisicamente quedaría algo así:

<div style="display: flex; justify-content: center; gap: 10px;">
  <img src="{{ site.baseurl }}/images/posts/trabajo-RAP/montaje1.png" alt="Montaje 1" width="300">
  <img src="{{ site.baseurl }}/images/posts/trabajo-RAP/montaje2.png" alt="Montaje 2" width="300">
</div>

<br>

---

# Configuración

Las ***ACL*** ó *Access Control Lists* como tal son una tecnología de los routers de *CISCO*, pero en Mikrotik disponemos de un ***firewall*** que cumplirá la misma función. Para ello, tenemos varias opciones, las que detallaremos son la configuración mediante *protocolos de capa 7* y mediante *DNS*, aunque daremos más ideas al final.

En todas las pruebas trataremos de bloquear los dominios de [Tiktok](https://www.tiktok.com/).

<br>

## Configuración mediante Protocolos de Capa 7

El firewall del router nos permite definir objetos de tipo ***protocolo de capa 7***, éstos aplican a los protocolos de la Capa de Aplicación. Aquí se nos permite introducir tanto un *`name`*, que sería un dominio, como una *expresión regular* que coincida con múltiples dominios. En nuestro caso utilizaremos esta última:

![Image]({{ site.baseurl }}/images/posts/trabajo-RAP/layer7.png){:width="100%"}

A continuación, podemos utilizar dicho objeto para crear una regla de firewall que *dropee* todos los paquetes que coincidan con este filtro:

![Image]({{ site.baseurl }}/images/posts/trabajo-RAP/layer7-2.png){:width="100%"}

<div style="display: flex; justify-content: center; gap: 10px;">
  <img src="{{ site.baseurl }}/images/posts/trabajo-RAP/layer7-3.png" alt="Montaje 1" width="50%">
  <img src="{{ site.baseurl }}/images/posts/trabajo-RAP/layer7-4.png" alt="Montaje 2" width="50%">
</div>

<br>

Activamos la regla y vemos que por muchos paquetes que mandemos no llegan a su destino:

<div style="display: flex; justify-content: center; gap: 10px;">
  <img src="{{ site.baseurl }}/images/posts/trabajo-RAP/layer7-tiktok.png" alt="Montaje 1" width="50%">
  <img src="{{ site.baseurl }}/images/posts/trabajo-RAP/layer7-http.png" alt="Montaje 2" width="50%">
</div>

<br>

Si quisiéramos configurarlo más rápidamente, los comandos necesarios para ello son:

```
/ip firewall layer7-protocol add name=block_tiktok regexp="^.+(tiktok|byteoversea|musical.ly|tiktokcdn).(com|net|org).*$"

/ip firewall filter add chain=forward layer7-protocol=block_tiktok action=drop comment="Bloquear TikTok"

/ip firewall layer7-protocol print
/ip firewall filter print
```

<br>

## Configuración mediante DNS

Si utilizamos nuestro router como servidor DNS de la red podemos bloquear el tráfico a nivel de DNS. De esta forma, cuando algún host pregunte a qué IP se resuelve el dominio de Tiktok, e lservidor DNS le devolverá una IP inválida.

Hay que resaltar que este método tiene dos problemas notables. El primero, es que si tratamos de acceder a la web mediante la dirección IP, no se aplicará la restricción. Y la segunda es que cada host podría configurar individualmente, de forma que cambiara el router por otro servidor DNS que no aplica el bloqueo que queremos.

Con esto en mente, comenzamos la configuración en la pestaña DNS del router, donde debemos activar la casilla `AllowRemoteRequests` para permitir que el router actúe como servidor DNS. Después, en la sección `static`, definimos una nueva entrada DNS con la misma expresión regular de antes:

![Image]({{ site.baseurl }}/images/posts/trabajo-RAP/dns1.png){:width="100%"}

<br>

A continuación, debemos añadir al servidor DHCP del router a sí mismo como servidor DNS por defecto:

![Image]({{ site.baseurl }}/images/posts/trabajo-RAP/dns-dhcp.png){:width="100%"}

<br>

Y finalmente, debemos añadir la siguiente regla al firewall para que *"obligue"* a las peticiones DNS a pasar por el router:

![Image]({{ site.baseurl }}/images/posts/trabajo-RAP/dns2.png){:width="100%"}

<br>

Una vez activado deberíamos ver cómo las peticiones a `www.tiktok.com` se redirigen a `127.0.0.1`:

![Image]({{ site.baseurl }}/images/posts/trabajo-RAP/tiktok-denied.png){:width="100%"}

<br>

## Otros métodos

Con los dos métodos expuestos trabajando juntos ya debería ser más que suficiente para implementar la funcionalidad que deseamos. Aunque en ocasiones puede hacer falta otro tipo de reglas.

<br>

### Bloqueo por contenido

En este caso, utilizaremos el campo `content` de las reglas del firewall, para especificar un contenido que de ser encontrado en un paquete hará que sea rechazado. De esta forma, tenemos el inconveniente de que pueden existir falsos positivos dependiendo de qué contenido se especifique.

<br>

### Bloqueo por TLS Hosts

Para este método, configuraremos la opción de ***TLS Hosts***, que intercepta los *handshakes* al inicio de una comunicación encriptada. Este método sólo funciona para http**s**.

<br>

### Bloqueo por dirección IP

Finalmente, tenemos la opción de bloquear por IP. Sin embargo, para aplicaciones tan grandes como Tiktok, es difícil conocer todos los rangos de IP que se manejan.

<br>

## Conclusión

Con estos métodos podemos bloquear tráfico a páginas web haciendo uso de un router Mikrotik. Además, combinados con las opciones de horarios ó aplicados a diferentes VLANs, tenemos una opción fácil y económica para añadir una capa extra de seguridad a nuestro hogar.

Si te gustan mis posts, ¡no dudes en leer el resto y estar pendiente a próximos proyectos!

<br>