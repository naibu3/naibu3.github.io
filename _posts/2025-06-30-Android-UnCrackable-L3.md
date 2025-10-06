---
layout: post
title: Android UnCrackable L3
comments: true
categories: [Mobile, Writeups]
---

Vamos a por el nivel 3 de UnCrackable, una de las aplicaciones vlunerables del [OWASP MASTG](https://mas.owasp.org/crackmes/Android/). De forma similar a los niveles anteriores, se nos da una aplicación que a priori detecta si nuestro dispositivo está rooteado, y de ser así nos cierra la aplicación.

<br>
![Image]({{ site.baseurl }}/images/posts/UnCrackableL3/UnCrackable-L3.png){:width="150px"}

# Reconocimiento

Vamos a comenzar echando un vistazo al código fuente con *jadx*. En la `MainActivity`, podemos ver algunas líneas interesantes, como una clave XOR `pizzapizzapizzapizzapizz`, la declaración de dos métodos nativos (`baz` e `init`) y la carga de una librería `libfoo.so`:

```java
private static final String TAG = "UnCrackable3";
static int tampered = 0;
private static final String xorkey = "pizzapizzapizzapizzapizz";
private CodeCheck check;
Map<String, Long> crc;

private native long baz();

private native void init(byte[] bArr);

[...]

static {
    System.loadLibrary("foo");
}
```

Al entrar se ejecuta la función `OnCreate`:

```java
public void onCreate(Bundle bundle) {
    verifyLibs();
    init(xorkey.getBytes());
    new AsyncTask<Void, String, String>() { // from class: sg.vantagepoint.uncrackable3.MainActivity.2
        /* JADX INFO: Access modifiers changed from: protected */
        @Override // android.os.AsyncTask
        public String doInBackground(Void... voidArr) {
            while (!Debug.isDebuggerConnected()) {
                SystemClock.sleep(100L);
            }
            return null;
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // android.os.AsyncTask
        public void onPostExecute(String str) {
            MainActivity.this.showDialog("Debugger detected!");
            System.exit(0);
        }
    }.execute(null, null, null);
    if (RootDetection.checkRoot1() || RootDetection.checkRoot2() || RootDetection.checkRoot3() || IntegrityCheck.isDebuggable(getApplicationContext()) || tampered != 0) {
        showDialog("Rooting or tampering detected.");
    }
    this.check = new CodeCheck();
    super.onCreate(bundle);
    setContentView(owasp.mstg.uncrackable3.R.layout.activity_main);
}
```

Esta función realiza una serie de operaciones:

- Llama a `verifyLibs`, que comprueba la integridad de las librerías nativas mediante el checksum CRC. Cabe recalcar que no se comprueba criptográficamente la firma de las mismas.
- Con `init`, inicialliza las librerías nativas, eviando como parámetro la clave XOR antes mencionada (`pizzapizzapizzapizzapizz`).
- Realiza una comprobación en busca de debuggers, privilegios de root ó tampering, en caso de enontrarlos sale del programa.

## Métodos de detección

Vamos a analizar cada método de detección por separado.

### Verificación de las librerías

La función es la siguiente:

```java
private void verifyLibs() {
    this.crc = new HashMap();
    this.crc.put("armeabi-v7a", Long.valueOf(Long.parseLong(getResources().getString(owasp.mstg.uncrackable3.R.string.armeabi_v7a))));
    this.crc.put("arm64-v8a", Long.valueOf(Long.parseLong(getResources().getString(owasp.mstg.uncrackable3.R.string.arm64_v8a))));
    this.crc.put("x86", Long.valueOf(Long.parseLong(getResources().getString(owasp.mstg.uncrackable3.R.string.x86))));
    this.crc.put("x86_64", Long.valueOf(Long.parseLong(getResources().getString(owasp.mstg.uncrackable3.R.string.x86_64))));
    try {
        ZipFile zipFile = new ZipFile(getPackageCodePath());
        for (Map.Entry<String, Long> entry : this.crc.entrySet()) {
            String str = "lib/" + entry.getKey() + "/libfoo.so";
            ZipEntry entry2 = zipFile.getEntry(str);
            Log.v(TAG, "CRC[" + str + "] = " + entry2.getCrc());
            if (entry2.getCrc() != entry.getValue().longValue()) {
                tampered = 31337;
                Log.v(TAG, str + ": Invalid checksum = " + entry2.getCrc() + ", supposed to be " + entry.getValue());
            }
        }
        ZipEntry entry3 = zipFile.getEntry("classes.dex");
        Log.v(TAG, "CRC[classes.dex] = " + entry3.getCrc());
        if (entry3.getCrc() != baz()) {
            tampered = 31337;
            Log.v(TAG, "classes.dex: crc = " + entry3.getCrc() + ", supposed to be " + baz());
        }
    } catch (IOException unused) {
        Log.v(TAG, "Exception");
        System.exit(0);
    }
}
```

La función comienza declarando un hashmap con los valores esperados para cada checksum, para después comprobarlos con los del propio apk. Podríamos tratar de saltar estas protecciones y modificar el programa, sin embargo no es lo más sencillo en este caso.

### Anti-debuggers

Se lanza una tarea en paralelo que detecta debuggers conectados al programa.

```java
    new AsyncTask<Void, String, String>() { // from class: sg.vantagepoint.uncrackable3.MainActivity.2
        /* JADX INFO: Access modifiers changed from: protected */
        @Override // android.os.AsyncTask
        public String doInBackground(Void... voidArr) {
            while (!Debug.isDebuggerConnected()) {
                SystemClock.sleep(100L);
            }
            return null;
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // android.os.AsyncTask
        public void onPostExecute(String str) {
            MainActivity.this.showDialog("Debugger detected!");
            System.exit(0);
        }
    }.execute(null, null, null);
```

### Anti-root

Finalmente, se lanzan las comprobaciones de los niveles anteriores para detectar el uso del superusuario.

```java
public class RootDetection {
    public static boolean checkRoot1() {
        for (String str : System.getenv("PATH").split(":")) {
            if (new File(str, "su").exists()) {
                return true;
            }
        }
        return false;
    }

    public static boolean checkRoot2() {
        String str = Build.TAGS;
        return str != null && str.contains("test-keys");
    }

    public static boolean checkRoot3() {
        for (String str : new String[]{"/system/app/Superuser.apk", "/system/xbin/daemonsu", "/system/etc/init.d/99SuperSUDaemon", "/system/bin/.ext/.su", "/system/etc/.has_su_daemon", "/system/etc/.installed_su_daemon", "/dev/com.koushikdutta.superuser.daemon/"}) {
            if (new File(str).exists()) {
                return true;
            }
        }
        return false;
    }
}
```

En esta parte también se comprueba que la flag de debug no esté activa:

```java
public class IntegrityCheck {
    public static boolean isDebuggable(Context context) {
        return (context.getApplicationContext().getApplicationInfo().flags & 2) != 0;
    }
}
```

## Analizando las librerías externas

Podemos analizar la librería `libfoo.so` con algun decompilador como `ghidra`.

### Anti-hook

Comenzaremos con la función `init`:

```c
void _INIT_0(void)

{
  long lVar1;
  int result;
  pthread_t thread;
  long canary;
  
  lVar1 = tpidr_el0;
  canary = *(long *)(lVar1 + 0x28);
  result = pthread_create(&thread,(pthread_attr_t *)0x0,FUN_001030d0,(void *)0x0);
  DAT_00115040 = 0;
  DAT_00115048 = 0;
  DAT_00115038 = 0;
  DAT_00115050 = 0;
  DAT_00115054 = DAT_00115054 + 1;
  if (*(long *)(lVar1 + 0x28) == canary) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail(result);
}
```

Vemos que está utilizando `pthread_create` para iniciar un hilo de ejecución que ejecutará la función `FUN_001030d0`, esta parte tal vez tiene que ver con la detección de debuggers que vimos antes, ya que funcionaba en un hilo separado. Vamos a echar un vistazo a esa función:

```c
void FUN_001030d0(void)

{
  long lVar1;
  int iVar2;
  FILE *__stream;
  char *pcVar3;
  char *unaff_x19;
  pthread_t pStack_270;
  long lStack_268;
  char *pcStack_260;
  undefined *puStack_250;
  code *pcStack_248;
  char acStack_240 [512];
  
  puStack_250 = &stack0xfffffffffffffff0;
  __stream = fopen("/proc/self/maps","r");
  if (__stream == (FILE *)0x0) {
LAB_00103180:
    pcVar3 = "Error opening /proc/self/maps! Terminating...";
  }
  else {
    unaff_x19 = "/proc/self/maps";
    do {
      while (pcVar3 = fgets(acStack_240,0x200,__stream), pcVar3 == (char *)0x0) {
        fclose(__stream);
        usleep(500);
        __stream = fopen("/proc/self/maps","r");
        if (__stream == (FILE *)0x0) goto LAB_00103180;
      }
      pcVar3 = strstr(acStack_240,"frida");
    } while ((pcVar3 == (char *)0x0) &&
            (pcVar3 = strstr(acStack_240,"xposed"), pcVar3 == (char *)0x0));
    pcVar3 = "Tampering detected! Terminating...";
  }
  __android_log_print(2,"UnCrackable3",pcVar3);
  goodbye();
  pcStack_248 = _INIT_0;
  lVar1 = tpidr_el0;
  lStack_268 = *(long *)(lVar1 + 0x28);
  pcStack_260 = unaff_x19;
  iVar2 = pthread_create(&pStack_270,(pthread_attr_t *)0x0,FUN_001030d0,(void *)0x0);
  DAT_00115040 = 0;
  DAT_00115048 = 0;
  DAT_00115038 = 0;
  DAT_00115050 = 0;
  DAT_00115054 = DAT_00115054 + 1;
  if (*(long *)(lVar1 + 0x28) != lStack_268) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail(iVar2);
  }
  return;
}
```

De forma simplificada, se está abriendo el `/proc/self/maps`, que contiene el mapeo de memoria de todos los procesos, y uno a uno va comprobando si corresponde a `"frida"` o a `"xposed"`, dos de los debuggers más utilzados. Esta protección nos impide acoplarnos a un proceso para hookear funciones. Sin embargo, aunque resulte paradójico, podemos utilizar Frida para saltarnos esta protección.

Vemos que para salir se llama a la función `goodbye`.

### Anti-debug

Si nos fijamos ahora en la llamada JNI `init`, vemos la siguiente función:

```c
void Java_sg_vantagepoint_uncrackable3_MainActivity_init
               (long *param_1,undefined8 param_2,undefined8 param_3)

{
  char *__src;
  
  anti_debug();
  __src = (char *)(**(code **)(*param_1 + 0x5c0))(param_1,param_3,0);
  strncpy((char *)&DAT_00115038,__src,0x18);
  (**(code **)(*param_1 + 0x600))(param_1,param_3,__src,2);
  DAT_00115054 = DAT_00115054 + 1;
  return;
}
```

Esta función ejecuta una función que he llamado `anti_debug`:

```c
void anti_debug(void)

{
  long lVar1;
  __pid_t _Var2;
  uint uVar3;
  uint uVar4;
  ulong uVar5;
  pthread_t local_30;
  long local_28;
  
  lVar1 = tpidr_el0;
  local_28 = *(long *)(lVar1 + 0x28);
  _Var2 = fork();
  if (_Var2 == 0) {
    uVar3 = getppid();
    uVar5 = ptrace(PTRACE_ATTACH,(ulong)uVar3,0,0);
    if (uVar5 == 0) {
      waitpid(uVar3,(int *)&local_30,0);
      while( true ) {
        ptrace(PTRACE_CONT,(ulong)uVar3,0,0);
        uVar4 = waitpid(uVar3,(int *)&local_30,0);
        uVar5 = (ulong)uVar4;
        if (uVar4 == 0) break;
        if ((~(uint)local_30 & 0x7f) != 0) {
                    /* WARNING: Subroutine does not return */
          _exit(0);
        }
      }
    }
  }
  else {
    uVar3 = pthread_create(&local_30,(pthread_attr_t *)0x0,FUN_0010322c,(void *)0x0);
    uVar5 = (ulong)uVar3;
  }
  if (*(long *)(lVar1 + 0x28) == local_28) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail(uVar5);
}
```

Esta función implementa un método de protección que podemos llamar *self-debug*. Esto se aprovecha de que un programa sólo puede tener enlazado un debugger, por tanto, creando un proceso hijo evita que se pueda enlazar otro proceso.

# Explotación

En este punto tenemos varias protecciones que bypasear.

## Bypasear el anti-root

Lo primero es bypasear el anti-root. Para ello podemos simplemente ejecutar el siguiente script con Frida:

```java
Java.perform(function () {
    var System = Java.use('java.lang.System');

    System.exit.overload('int').implementation = function (code) {
        console.log('[Bypass] System.exit called with code:', code);
        // No hacer nada para evitar que la app termine
    };
});
```

Con eso ya podríamos empezar, pero aún hay que sortear el resto de protecciones.

## Bypasear las protecciones nativas

Como hemos visto antes, el programa comprobaba si se utilizaba frida mediante la función `strstr`. Por tanto, basta con hookear esa función y hacer que devuelva `null` como si no se hubiera encontrado nada. Para ello hookear funciones nativas con frida, se utiliza el `Interceptor`:

```java
Interceptor.attach(Module.findExportByName(null, 'strstr'), {
    onEnter: function (args) {
        // args[0] = haystack, args[1] = needle
        var haystack = Memory.readUtf8String(args[0]);
        var needle = Memory.readUtf8String(args[1]);
        console.log('strstr called with haystack:', haystack, 'needle:', needle);
    },
    onLeave: function (retval) {
        // Forzar retorno NULL
        retval.replace(ptr('0x0'));
        console.log('strstr hooked: forced return NULL');
    }
});
```

