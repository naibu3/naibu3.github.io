---
layout: post
title: AndroGOAT - Network Intercepting
comments: true
categories: [Mobile, Writeups]
---

En el post anterior estuvimos explotando algunas de las vulnerabilidades más típicas de Android en una aplicación destinada a ello, AndroGoat. Hoy vamos a concluir, explotando la sección de Intercepción de Tráfico de red.

<br>
![Image]({{ site.baseurl }}/images/posts/AndroGOAT/AndroGOAT.png){:width="300px"}

# HTTP

La primera parte consiste en interceptar tráfico http. Para ello comenzaremos configurando BurpSuite:

<br>
![Image]({{ site.baseurl }}/images/posts/AndroGOAT/BurpSuite-options.png){:width="500px"}

Y en las opciones de conexión del móvil especificamos el proxy:

<br>
![Image]({{ site.baseurl }}/images/posts/AndroGOAT/proxy.png){:width="300px"}

Con todo listo podemos lanzar la petición y verla desde BurpSuite:

<br>
![Image]({{ site.baseurl }}/images/posts/AndroGOAT/http-req.png){:width="300px"}

![Image]({{ site.baseurl }}/images/posts/AndroGOAT/burp-http-req.png){:width="300px"}

Vemos que somos capaces de ver las peticiones.

# HTTPS

Cuando tratamos de hacer un MITM a HTTPS, en un navegador veremos un aviso de que la comunicación no es privada. En aplicaiones móviles, no se mostrará el aviso y por tanto no seremos capaces de interceptar nada.

BurpSuite genera certificados autofirmados para los dispositivos a los que se conecta. El problema es que este certificado no es de confianza para android. Para ello debemos asegurarnos de tenerlo instalado, podemos descargarlo si accedemos por un navegador a `<IP-Burpsuite>:<Puerto>`:

<br>
![Image]({{ site.baseurl }}/images/posts/AndroGOAT/certificate.png){:width="300px"}

![Image]({{ site.baseurl }}/images/posts/AndroGOAT/certificate-install.png){:width="300px"}

## Posibles fallos

En versiones posteriores de la API (a partir de la API 24-Nougat), es posible que no sea posible interceptar las peticiones. Esto se debe al funcionamiento de los certificados, concretamente a partir de esa versión, las propias aplicaciones deben especificar en el `network_security_config.xml` que cofían explícitamente en el certificado.

Para bypasear esta protección, podemos ó instalar el certificado de burpsuite como un certificado a nivel de sistema. Ó, de forma más simple, modificar la aplicación para incorporar esta configuración. Con algo así sería suficiente:

```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
</network-security-config>
```

Hay una tercera forma de saltar esta protección, mediante frida. Para ello valdría con un script como el siguiente:

```java
if(Java.available)
{
	Java.perform(function () {

    var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');

    TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
		// https://github.com/google/conscrypt/blob/c88f9f55a523f128f0e4dace76a34724bfa1e88c/platform/src/main/java/org/conscrypt/TrustManagerImpl.java#L650 

        console.log(JSON.stringify(untrustedChain));
        return untrustedChain;
    }
});
}
else
{
	console.log("Java not available");
}
```

# Certificate pinning

En la última parte deberemos bypasear una técnica llamada **certificate pinning**. Esta técnica consiste en “anclar” la confianza de la aplicación a un certificado específico o a un conjunto reducido de certificados concretos, en lugar de confiar en cualquier certificado válido emitido por una autoridad certificadora del sistema.

Igual que antes, podemos parchear el binario, pero con frida y este [script](https://codeshare.frida.re/@akabe1/frida-multiple-unpinning/) debería ser suficiente.

```java
frida -U -N owasp.sat.agoat -l pin.js
```

<br>
![Image]({{ site.baseurl }}/images/posts/AndroGOAT/cert-pinning-solve.png){:width="300px"}

Y ahora sí, con esto habríamos completado por completo el AndroGOAT.