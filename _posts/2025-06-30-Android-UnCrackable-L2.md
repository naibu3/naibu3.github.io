---
layout: post
title: Android UnCrackable L2
comments: true
categories: [Mobile, Writeups]
---

Seguimos con la explotación de dispositivos Android. En este caso traemos la segunda parte de una de las aplicaciones incluidas en el [OWASP MASTG](https://mas.owasp.org/crackmes/Android/). Igual que en el nivel 1, se nos da una aplicación que a priori detecta si nuestro dispositivo está rooteado, y de ser así nos cierra la aplicación.

<br>
![Image]({{ site.baseurl }}/images/posts/UnCrackableL2/UnCrackable-L2.png){:width="150px"}

# Reconocimiento

Vemos que al igual que antes, se apican una serie de comprobaciones. 

```java
public class b {
    public static boolean a() {
        for (String str : System.getenv("PATH").split(":")) {
            if (new File(str, "su").exists()) {
                return true;
            }
        }
        return false;
    }

    public static boolean b() {
        String str = Build.TAGS;
        return str != null && str.contains("test-keys");
    }

    public static boolean c() {
        for (String str : new String[]{"/system/app/Superuser.apk", "/system/xbin/daemonsu", "/system/etc/init.d/99SuperSUDaemon", "/system/bin/.ext/.su", "/system/etc/.has_su_daemon", "/system/etc/.installed_su_daemon", "/dev/com.koushikdutta.superuser.daemon/"}) {
            if (new File(str).exists()) {
                return true;
            }
        }
        return false;
    }
}

[...]

public void onCreate(Bundle bundle) {
   init();
   if (b.a() || b.b() || b.c()) {
      a("Root detected!");
   }
   if (a.a(getApplicationContext())) {
      a("App is debuggable!");
   }
   [...]
```

Si vemos las comprobaciones, en ambos casos se llama a la misma función, que llama a `System.exit`:

```java
public void a(String str) {
   AlertDialog create = new AlertDialog.Builder(this).create();
   create.setTitle(str);
   create.setMessage("This is unacceptable. The app is now going to exit.");
   create.setButton(-3, "OK", new DialogInterface.OnClickListener() { // from class: sg.vantagepoint.uncrackable2.MainActivity.1
      @Override // android.content.DialogInterface.OnClickListener
      public void onClick(DialogInterface dialogInterface, int i) {
            System.exit(0);
      }
   });
   create.setCancelable(false);
   create.show();
}
```

# Hookeando la fución con Frida

Haciendo uso de Frida, podemos convertir la llamada a `a` en una función vacía, saltando la protección. Para ello, al igual que antes, debemos ejecutar `frida-server` en el dispositivo víctima:

```bash
adb push frida-server /data/local/tmp
adb shell
su
cd /data/local/tmp/
./frida-server
```

A continuación, creamos un script `bypass-check.js` (créditos a [Niklas](https://nibarius.github.io/learning-frida/2020/05/23/uncrackable2)):

```java
Java.perform(function () {
    var MainActivity = Java.use("sg.vantagepoint.uncrackable2.MainActivity");
      MainActivity.a.overload("java.lang.String").implementation = function(s) {
        console.log("Tamper detection suppressed, message was: " + s);
      }
});
```

Como la aplicación no se mantiene abierta, vamos a hacer que Frida la *spawnee*:

```bash
frida -U -f owasp.mstg.uncrackable2 -l bypass-check.js

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
   . . . .   Connected to Mi Note 10 (id=b61dd82c)
Spawned `owasp.mstg.uncrackable2`. Resuming main thread!                
[Mi Note 10::owasp.mstg.uncrackable2 ]-> Tamper detection suppressed, message was: Root detected!
```

<br>
![Image]({{ site.baseurl }}/images/posts/UnCrackableL2/UnCrackable-Main.png){:width="200px"}
<br>

# Obteniendo el código de verificación

```java
local_38 = 0x6e616854;   // 'Than'
uStack_34 = 0x6620736b;  // 'ks f'
uStack_30 = 0x6120726f;  // 'or a'
uStack_2c = 0x74206c6c;  // 'll t'
local_28 = 0x68736966206568; // 'he fisih' -> probablemente mal decompilado: 'he fish'
```

Si lo introducimos en el programa podremos superar el reto!

<br>
![Image]({{ site.baseurl }}/images/posts/UnCrackableL2/UnCrackable-Solution.png){:width="200px"}
<br>
