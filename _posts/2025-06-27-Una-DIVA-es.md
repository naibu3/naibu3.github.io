---
layout: post
title: Una DIVA es... Vulnerable?
comments: true
categories: [Mobile, Writeups]
---

Como dijo Melody en Eurovisión, *Una diva es valiente, poderosa* y vulnerable??? En este post estaremos superando los retos de DIVA ó *Damn Vulnerable and Insecure App*, este es un proyecto para aprender lo básico sobre explotación en Android.

# Instalación

Lo mejor es instalar la aplicación en un dispositivo *rooteado*, conectado al equipo mediante USB. Para instalarla podemos hacerlo mediante la herramienta **adb**:

```bash
adb install DIVA.apk
```

Una vez instalada veremos un menú con los siguientes niveles:

# Insecure Loging

El primer nivel nos muestra un campo que espera un número de tarjeta de crédito. Nos piden que veamos como se está logueando la información. Si descompilamos con **jadx** veremos como se está

Con **adb** podemos ver los logs:

```bash
adb logcat | grep -i "Error while"

06-27 12:17:52.106 22839 22839 E diva-log: Error while processing transaction with credit card: <El número que hemos introducido>
```

# Hardcoding Issues - Part 1

En el segundo nivel vemos una vista similar a la anterior que nos solicita una clave. Si inspeccionamos el código veremos lo siguiente:

# Insecure Data Storage - Part 1

En este nivel se nos da una especie de logging, y se nos pide que encontremos donde se almacenan las credenciales. Decompilando el programa, vemos que se almacenan en la configuración por defecto:

Podemos acceder a ella con **adb**:

```bash
adb shell

su

cd /data/data/jakhar.aseem.diva/shared_prefs

cat jakhar.aseem.diva_preferences.xml                                                         
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="password">password</string>
    <string name="notespin">5569</string>
    <string name="user">naibu3</string>
</map>
```

Y podríamos ver la información que hay almacenada. Hay que recalcar que si no introducimos unas credenciales rpreviamente, el archivo no existirá.

# Insecure Data Storage - Part 2

En este segundo nivel las credenciales parecen almacenarse en una base de datos:

No podemos extraerla directamente, pero podemos copiarla en `/data/local/tmp`, ya que ahí tenemos permisos:

Y con **sqlite3** podemos ver la tabla `myuser`:



# Insecure Data Storage - Part 3

Este nivel es muy similar, pero en este caso se almacenan en texto plano en un archivo:

```bash
tucana:/data/data/jakhar.aseem.diva # cat uinfo8847310758726822991tmp                                                                            
naibu3:naibu3
```

# Insecure Data Storage - Part 4

Este último nivel es igual que el anterior, pero se trata de u archivo oculto:


