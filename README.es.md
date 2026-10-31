# AgentScan

**English** | [Español](README.es.md)

Un pequeño escáner para el proceso de Minecraft (Java Edition, JVM HotSpot en Windows x64). Busca **rastros de agentes JVMTI, agentes Java (`java.lang.instrument`) y manipulaciones del entorno de la máquina virtual**. Detecta tanto los agentes que están activos en ese momento como los que ya se han desvinculado.

La idea principal: conectar un agente cambia de forma irreversible el estado de la máquina virtual. El código del agente puede descargarse, el transformador puede eliminarse y el entorno JVMTI puede liberarse. Pero la VM sigue recordando que el agente estuvo allí:

- una entrada en su propia lista de agentes;
- un entorno JVMTI con el número mágico «disposed»;
- una marca establecida por el mecanismo de attach;
- una entrada de redefinición de clases en un registro circular;
- un contador de redefiniciones en el espejo de la clase.

AgentScan lee estos registros de la memoria del proceso sin detener el juego ni adjuntarle un depurador.

---

## Índice

- [Inicio rápido](#inicio-rápido)
- [Salida](#salida)
- [Qué detecta](#qué-detecta)
  - [1. Entornos JVMTI](#1-entornos-jvmti)
  - [2. Agentes Java y mecanismo de attach](#2-agentes-java-y-mecanismo-de-attach)
  - [3. Caja negra de la VM y redefinición de clases](#3-caja-negra-de-la-vm-y-redefinición-de-clases)
  - [4. Entorno Java](#4-entorno-java)
  - [5. Firmas en memoria](#5-firmas-en-memoria)
- [Cómo funciona](#cómo-funciona)
- [Limitaciones](#limitaciones)
- [Prueba positiva](#prueba-positiva)
- [Compilación](#compilación)

---

## Inicio rápido

### Interfaz gráfica

Ejecuta `AgentScan.exe` con un doble clic, preferiblemente **como administrador**.

1. La lista muestra inmediatamente los procesos `javaw.exe` y `java.exe` con el formato `PID Título de la ventana - memoria en GB`; por ejemplo, `4992 Minecraft* 1.21.10 - 1.17 GB`. Las ventanas de Minecraft aparecen en la parte superior y están preseleccionadas. Si el juego se inició después, pulsa «Refresh».
2. «Scan»: la barra muestra el progreso del análisis y, debajo, el paso actual (el análisis completo de memoria también muestra un porcentaje).
3. Al finalizar, verás el veredicto (rojo, amarillo o verde) y los contadores de hallazgos. Hay dos botones:
   - **«Result»** abre la carpeta `reports` y selecciona el informe HTML;
   - **«In browser»** abre el informe en el navegador predeterminado. El navegador se obtiene del controlador de enlaces `http`, no de la asociación de archivos `.html`: esta última suele apuntar a un editor.

Si cierras la ventana durante un análisis, el escáner solicita confirmación y se cierra después del paso actual.

Si no tienes permisos de administrador, aparecerá una advertencia en la parte inferior de la ventana: en ese caso, solo estarán disponibles los procesos del usuario actual.

### Consola

Cualquier argumento activa el modo consola (misma salida y mismos códigos de salida):

```bat
AgentScan.exe --console
AgentScan.exe --pid 1234
AgentScan.exe --list
```

Con `--console`, el proceso de Minecraft se detecta automáticamente. Si hay varios procesos coincidentes, especifica `--pid`. El exe está compilado como una aplicación con interfaz gráfica, por lo que en `cmd` el prompt vuelve antes de que termine la salida. Para esperar a que finalice y obtener el código de salida, ejecútalo mediante `start /wait AgentScan.exe --pid 1234`. En PowerShell, la espera se realiza automáticamente cuando se redirige la salida (`| ...`, `> file`).

El equipo analizado no necesita .NET si utilizas el `AgentScan.exe` completo (archivo único e independiente). La versión ligera `AgentScan-lite.exe` (~1 MB) necesita .NET 8 Desktop Runtime; consulta [Compilación](#compilación).

| Opción | Función |
|---|---|
| `--pid, -p <N>` | PID del proceso del juego (se detecta automáticamente de forma predeterminada) |
| `--list, -l` | mostrar los procesos Java y salir |
| `--console, -c` | modo consola con detección automática del proceso |
| `--out, -o <dir>` | directorio de informes (predeterminado: `reports`, junto al exe) |
| `--dump-dir <dir>` | directorio para los volcados de los residuos encontrados |
| `--verbose, -v` | salida detallada en la consola |
| `--max-dump <MB>` | límite para un volcado (predeterminado: 256 MB) |
| `--no-strings` | omitir el análisis completo de memoria: es más rápido, pero algunas comprobaciones no tendrán datos |
| `--no-dump` | no guardar volcados |
| `--fast` | equivalente a `--no-strings --no-dump` |
| `--only <part,...>` | ejecutar solo los pasos cuyo nombre contenga una subcadena (depuración del escáner; el informe se marca como incompleto) |
| `--skip <part,...>` | omitir esos pasos |

---

## Salida

1. **Consola** (en la ventana: veredicto y contadores): hallazgos agrupados por gravedad (CRITICAL → HIGH → MEDIUM → LOW). Al final: totales, tiempo y un veredicto de una línea.
2. **`reports/agentscan-<pid>-<time>.html`**: informe para consultar. Incluye el veredicto, contadores, filtros por gravedad y categoría, búsqueda, temas oscuro y claro, y un **selector de idioma EN / ES** (inglés de forma predeterminada; la elección se recuerda). Cada hallazgo incluye una explicación del mecanismo y los datos sin procesar. La pestaña «Full data» contiene las secciones completas: entornos JVMTI, indicadores de la VM, registros de eventos y propiedades del entorno de ejecución.
3. **`agentscan-<pid>-<time>.txt`**: el mismo informe en texto completo (en inglés).
4. **`agentscan-<pid>-<time>.json`**: para procesamiento automatizado (en inglés).
5. **`reports/agentscan-dumps-<time>/`**: volcados de los residuos encontrados (entornos, registros de agentes y estructuras JPLIS), si los hay.

Niveles de gravedad de los hallazgos:

| Nivel | Significado |
|---|---|
| **CRITICAL** | evidencia prácticamente inequívoca |
| **HIGH** | indicio sólido que requiere explicación |
| **MEDIUM** | requiere revisión manual |
| **LOW** | anomalía débil, también presente en procesos limpios |
| **INFO** | referencia, no evidencia |

Códigos de salida: `10` — se encontró CRITICAL, `9` — se encontró HIGH, `8` — se encontró MEDIUM, `0` — limpio, `2` — proceso no encontrado, `3` — error fatal.

---

## Qué detecta

A continuación se enumeran todas las comprobaciones por grupo. La gravedad indicada es la que asigna el escáner.

### 1. Entornos JVMTI

Un entorno JVMTI (`JvmtiEnvBase`) es el objeto que la VM crea para cada agente cuando se llama a `GetEnv(JVMTI_VERSION)`. Almacena todo lo que el agente solicitó a la máquina. **Cuando el agente se desvincula, el objeto no se elimina**: HotSpot solo cambia el número mágico de `0x71EE` (activo) a `0xDEFC` (liberado mediante `DisposeEnvironment`).

| Comprobación | Qué se busca | Gravedad |
|---|---|---|
| **Lista de entornos de la VM** (recorrido de `JvmtiEnvBase::_head_environment` mediante VMStructs activas) | todos los entornos, incluidos los liberados; número mágico y estado | CRITICAL |
| **Entornos fuera de la lista** | objetos de entorno encontrados en memoria, pero desvinculados de la lista de la VM | CRITICAL |
| **Suscripción a `ClassFileLoadHook`** | el agente recibe el bytecode de cada clase cargada y puede modificarlo | CRITICAL |
| **Callbacks de eventos que no llevan a ninguna parte** | los controladores de eventos apuntan a memoria fuera de los módulos cargados: la biblioteca del agente se ha descargado, pero el entorno conserva sus direcciones | CRITICAL |
| **Capacidades del agente** (`jvmtiCapabilities`) | 45 capacidades con nombre que solicitó el agente: `can_redefine_classes`, `can_retransform_classes`, `can_generate_breakpoint_events`, `can_tag_objects`… Permanecen registradas para siempre | parte del hallazgo |
| **Mapa de etiquetas de objetos** | el agente etiquetó objetos del heap; se recuperan las clases de los objetos etiquetados | CRITICAL |
| **Prefijos de métodos nativos** (`SetNativeMethodPrefix`) | cadenas establecidas por el autor del agente | CRITICAL |
| **Datos propios del agente** (`_env_local_storage`) | un puntero a la estructura del agente, su volcado y sus cadenas | CRITICAL |
| **Indicadores estáticos de `JvmtiExport`** | `_can_hotswap_or_post_breakpoint`, `_can_access_local_variables`, `_can_post_on_exceptions`, `_can_walk_any_space`. La VM los establece cuando un agente solicita las capacidades correspondientes | CRITICAL |
| **Puntos de interrupción JVMTI** | un `InstanceKlass::_breakpoints` distinto de cero o un contador de puntos de interrupción de método. Solo `SetBreakpoint` los rellena | CRITICAL |
| **Objetos `JvmtiAgentThread`, `JvmtiBreakpoint`** | búsqueda mediante la dirección exacta de la vtable obtenida de las exportaciones de `jvm.dll` | CRITICAL |
| **Búsqueda independiente del número mágico** | los entornos se buscan mediante `0x71EE/0xDEFC/0xDEAD` con verificación estructural (versión JVMTI, `_next`, 37 posiciones de callback, referencia inversa del mapa de etiquetas). Borrar el puntero de la vtable no sirve de ayuda | CRITICAL |
| **Estructuras que contienen un entorno** | quién almacena un puntero `jvmtiEnv`: `JPLISAgent` (la parte nativa de `java.lang.instrument`) o las propias estructuras del agente nativo | HIGH / CRITICAL |
| **Tablas `jvmtiInterface_1_` / `JNINativeInterface_`** | posiciones de las tablas de funciones de `jvm.dll` redirigidas fuera de ella (hook) | CRITICAL |
| **Tabla `JavaVM`** (`JNIInvokeInterface_`) | `AttachCurrentThread`/`GetEnv` redirigidos fuera de `jvm.dll` | CRITICAL |

Un entorno cuyos controladores apuntan todos a la propia `jvm.dll` se considera interno (así es como Flight Recorder crea su entorno) y no se informa como agente externo.

### 2. Agentes Java y mecanismo de attach

| Comprobación | Qué se busca | Gravedad |
|---|---|---|
| **Lista de agentes de HotSpot** (`JvmtiAgentList` en JDK 21, `AgentLibrary` en JDK 8–17) | el registro de un agente no se elimina ni siquiera después de `Agent_OnUnload`. Proporciona el nombre, las opciones (para un agente Java, la ruta a su jar), la ruta de la biblioteca, el identificador de la biblioteca (si se ha descargado) y el puntero JPLIS. En JDK 21+, también se lee la marca «attached to a running VM» | CRITICAL (attach o agente desconocido), HIGH (agente conocido al inicio) |
| **Objetos del mecanismo de attach** (`AttachOperation`, `Win32AttachOperation`, `JVMTIAgentLoadDCmd`) | un objeto con el nombre de comando **rellenado** (`load`, `jcmd`, `setflag`…): se enviaron comandos externos a la VM en ejecución | CRITICAL |
| **Indicadores de la VM: origen `ATTACH_ON_DEMAND`** | un indicador modificado mediante attach mientras la VM estaba en ejecución. Los bits de origen se encuentran en los datos estáticos de `jvm.dll` y no se pueden borrar | CRITICAL |
| **Indicadores de la VM: origen `MANAGEMENT`** | un ajuste modificado desde dentro del proceso mediante `HotSpotDiagnosticMXBean`. El juego no hace esto | HIGH |
| **Argumentos del agente en la copia de la VM** | `-javaagent`, `-agentlib`, `-agentpath`, `-Xbootclasspath` en la copia propia de los argumentos de la VM (`Arguments::_jvm_args_array`) | CRITICAL |
| **Conciliación de las tres copias de la línea de comandos** | la copia de la VM, el bloque de parámetros del proceso (PEB) y los contadores hsperfdata. Un argumento presente en la VM, pero no en el PEB, procede de `JAVA_TOOL_OPTIONS` o el PEB se limpió. Un indicador marcado como establecido en la línea de comandos, pero ausente de la copia de argumentos, se escribió sin pasar por el análisis de argumentos | HIGH / CRITICAL |
| **Indicadores relacionados con attach** | `EnableDynamicAgentLoading`, `DisableAttachMechanism`, `StartAttachListener`, `AllowRedefinitionToAddDeleteMethods`, `UnlockDiagnosticVMOptions` y otros establecidos explícitamente | MEDIUM / HIGH |
| **Variables de entorno** | `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS`, `JDK_JAVA_OPTIONS`. Con un indicador de agente: CRITICAL; si no están vacías y no contienen un agente: MEDIUM (TLauncher establece `_JAVA_OPTIONS=` vacío, lo que es INFO) | CRITICAL / MEDIUM |
| **Módulos del agente** | `instrument.dll`, `jdwp.dll` cargados (CRITICAL), `attach.dll` (HIGH); cualquier módulo que exporte `Agent_OnLoad` / `Agent_OnAttach` / `Agent_OnUnload` (CRITICAL) | CRITICAL / HIGH |
| **Hilos del agente** | `JVMTI Agent Thread` (CRITICAL), `JDWP…` y `Java Debug…` (HIGH). El hilo `Attach Listener` siempre se crea en Windows y no constituye evidencia | CRITICAL / HIGH |
| **Objeto `InstrumentationImpl`** | activo o en la zona muerta del heap. **Un cliente Fabric limpio no tiene ninguno.** Se leen la dirección del agente nativo, las capacidades negociadas y ambas listas de transformadores | CRITICAL |
| **Objetos `ClassFileTransformer`** | todos los objetos de clases que implementan un transformador, incluso los eliminados mediante `removeTransformer`, indicando si la clase está en los archivos del juego | CRITICAL |
| **Clases del mecanismo de agente** | clases `sun/instrument/*`, `java/lang/instrument/*` cargadas (la VM solo las carga cuando se conecta un agente y nunca las descarga) | HIGH |
| **Bytecode de clases del agente en memoria** | `sun/instrument/InstrumentationImpl`, `java/lang/instrument/*`, `sun/tools/attach/*`, `com/sun/tools/attach/VirtualMachine` (CRITICAL), `jdk/internal/agent/` (MEDIUM) | CRITICAL / MEDIUM |
| **Agente en los contadores hsperfdata** | un indicador de agente en `java.rt.vmArgs` / `sun.rt.javaCommand`: lo que la VM registró sobre sí misma al iniciarse, independientemente del PEB | CRITICAL |
| **Área hsperfdata no encontrada** | desactivada mediante `-XX:-UsePerfData` / `-XX:+PerfDisableSharedMem`, por lo que no se puede verificar el inicio | HIGH (MEDIUM si el indicador es visible) |

### 3. Caja negra de la VM y redefinición de clases

HotSpot escribe registros circulares de eventos para el informe de fallos (`Events::log`). Estos sobreviven a la desvinculación del agente y a la descarga de sus clases.

| Comprobación | Qué se busca | Gravedad |
|---|---|---|
| **Registro `Classes redefined`** | cualquier entrada: nombres de las clases redefinidas y hora de la redefinición. Solo lo escriben `RedefineClasses` / `RetransformClasses` | CRITICAL |
| **Descarga de bibliotecas nativas** (`Unloaded dll`) | el cliente de Minecraft nunca descarga sus bibliotecas | CRITICAL |
| **Bibliotecas del registro que ya no están en el proceso** | la VM recuerda la carga, pero el módulo ya no está | CRITICAL |
| **Bibliotecas cargadas tardíamente** | cargadas mucho después que las demás | HIGH |
| **Clases de los registros de carga/descarga que no están en los archivos del juego** | | HIGH / CRITICAL |
| **Registros vacíos después de más de un minuto de ejecución** | se borró el contenido: la propia VM nunca restablece el contador de entradas | CRITICAL |
| **`-XX:-LogEvents` / `LogEventsBufferEntries` reducido** | el registro de vuelo se desactivó deliberadamente | HIGH |
| **Operaciones del agente en el registro circular `VM Operations`** | `RedefineClasses`, `ChangeBreakpoints`, `GetOrSetLocal`, `HeapWalkOperation`, `GetAllStackTraces`, `ForceEarlyReturn`… El juego nunca las llama | HIGH |
| **Indicadores de redefinición en los métodos** | `IS_OLD`, `IS_OBSOLETE`, `IS_DELETED`, `IS_PREFIXED_NATIVE` en objetos `Method`. Solo los establecen `RedefineClasses`, `RetransformClasses` y `SetNativeMethodPrefix` | CRITICAL |
| **Metadatos huérfanos** | objetos `Klass`/`Method`/`ConstantPool` inaccesibles desde el grafo de cargadores, con nombres significativos (no de ejecución): residuos de versiones antiguas de clases redefinidas | MEDIUM |
| **Contador de redefiniciones en el espejo de clase** (`Class.classRedefinedCount`) | recuento exacto de redefiniciones por clase durante toda la vida del proceso, incluidas las clases que ya han salido del registro de 20 entradas | CRITICAL |
| **Varias copias de bytecode de una clase** | rastro de transformación (bytes originales y modificados) | INFO |
| **Conciliación de cuatro fuentes** (registro, indicadores de métodos, código compilado no válido y contadores del espejo) | discrepancias: hay indicadores, pero el registro está vacío (se borró); hay registro, pero no indicadores; código muerto en la caché de código sin entradas de vaciado. También bandas contiguas de código no válido por número de compilación (se invalidó una clase entera) y ráfagas densas de desoptimización | CRITICAL / HIGH / MEDIUM |

### 4. Entorno Java

| Comprobación | Qué se busca | Gravedad |
|---|---|---|
| **`jdk.attach.allowAttachSelf=true`** | el proceso puede conectarse a sí mismo mediante el mecanismo de attach: así es como el código que ya se está ejecutando dentro del juego inyecta un agente sin un cargador externo | CRITICAL |
| **`System.props` frente a la instantánea `VM.savedProps`** | propiedades añadidas por código que ya está en ejecución; propiedades clave reescritas (`java.class.path`, `java.library.path`, `sun.boot.library.path`, `java.home`, `java.system.class.loader`…); propiedades eliminadas con `System.clearProperty` | HIGH / MEDIUM |
| **Paquetes abiertos de `java.base`** | `--add-opens` o `Modules.addOpens` durante la ejecución. El mapa de aperturas nunca se borra; un cliente limpio tiene cero aperturas de `java.base` | HIGH |
| **Bibliotecas nativas según Java** (`NativeLibraries`) | una biblioteca figura como cargada por Java, pero su módulo no está en el proceso (se descargó); una biblioteca cargada por una clase que no está en ningún archivo del juego | HIGH / CRITICAL |
| **Clases en cargadores privilegiados** | una clase que no pertenece al JDK en el cargador bootstrap o platform. Así funcionan `-Xbootclasspath/a`, `Instrumentation.appendToBootstrapClassLoaderSearch` y JNI `DefineClass` con un cargador nulo | CRITICAL |
| **Un cargador que es en sí mismo una clase oculta** | código cargado por un cargador cuyo nombre no se puede encontrar | CRITICAL |
| **Cargador nulo adicional** | más de un `ClassLoaderData` sin objeto de cargador y sin la marca de clase oculta | HIGH |

### 5. Firmas en memoria

Un análisis completo de toda la memoria del proceso en una sola pasada. El conjunto de cadenas solo cubre JVMTI, `java.lang.instrument` y los mecanismos de attach. Cada cadena se busca únicamente en zonas donde una VM limpia no puede tenerla (por ejemplo, solo en memoria ejecutable privada: `jvm.dll` y `lib/modules` siempre contienen estas cadenas).

| Cadena | Dónde se busca | Gravedad |
|---|---|---|
| `Agent_OnAttach`, `Agent_OnUnload` | memoria ejecutable privada | HIGH |
| Nombres de funciones JVMTI: `RetransformClasses`, `RedefineClasses`, `GetLoadedClasses`, `SetEventNotificationMode`, `AddCapabilities`, `IterateOverInstancesOfClass`, `GetObjectsWithTags`, `FollowReferences`, `DisposeEnvironment` | memoria ejecutable privada | HIGH |
| `SetJNIFunctionTable`, `GetJNIFunctionTable` | memoria ejecutable privada | CRITICAL |
| `JNI_GetCreatedJavaVMs`, `AttachCurrentThread` | memoria ejecutable privada | HIGH |
| `\\.\pipe\javatool` (canal Dynamic Attach) | memoria privada | CRITICAL |
| `JPLISAgent`, `loadAgentLibrary`, `loadClassAndCallPremain`, `loadClassAndCallAgentmain` | memoria privada | HIGH |
| `appendToSystemClassLoaderSearch`, `appendToBootstrapClassLoaderSearch` | memoria privada | CRITICAL |
| `net/bytebuddy/agent`, `net/bytebuddy/` | memoria privada | HIGH |
| `javassist/`, `redefineModule` | memoria privada | MEDIUM |
| `sun/instrument/InstrumentationImpl`, `TransformerManager`, `addTransformer`, `retransformClasses`, `defineAnonymousClass` | memoria privada | LOW: también aparecen ocurrencias aisladas en una VM limpia; solo la comprobación estructural es concluyente |

El conjunto se puede ampliar con un archivo `signatures.json` junto al exe (una matriz de objetos `{name, category, text, severity, scope, utf16, wholeWord, note}`).

---

## Cómo funciona

1. **Fundamentos.** Mapa de memoria, módulos, hilos y tablas JNI/JVMTI en los datos de `jvm.dll`.
2. **VMStructs en vivo.** Se lee `gHotSpotVMStructs` de las exportaciones de `jvm.dll`: la tabla de desplazamientos reales de campos de esta compilación de HotSpot. Se utiliza para recorrer el grafo de cargadores de clases, la lista de entornos JVMTI, la tabla de indicadores de la VM y la copia de argumentos. Los desplazamientos no están codificados de forma fija, por lo que el escáner es compatible con distintas versiones del JDK.
3. **Análisis completo de memoria.** Una pasada por toda la memoria legible. Encuentra firmas, archivos de clases Java, objetos de metaspace mediante direcciones exactas de vtable, objetos del registro de eventos de la VM y referencias a las tablas JNI/JVMTI.
4. **Heap de Java.** Los objetos se leen mediante los nombres de campos de la plataforma: `InstrumentationImpl`, transformadores, propiedades, módulos, bibliotecas nativas y espejos de clases. También se lee la zona muerta del heap, es decir, los restos de objetos recolectados.
5. **Pasos auxiliares** (lista de módulos, nombres de hilos y bloques de la caché de código) recopilan únicamente lo que necesitan las comprobaciones anteriores.

El escáner **solo lee** la memoria del proceso: no conecta agentes, no realiza operaciones de attach, no escribe en el proceso ni detiene los hilos del juego.

---

## Limitaciones

- **Solo Windows x64 y HotSpot** (Oracle/OpenJDK/Temurin, etc.). OpenJ9 no es compatible.
- **La marca «attached to a running VM» en el registro del agente** solo se lee en JDK 21+. El registro `AgentLibrary` de JDK 8–17 no tiene ese campo; en esas versiones, el método de attach se determina a partir de otros rastros: argumentos, objetos de attach e indicadores de la VM.
- **Un resultado limpio no demuestra nada por sí solo.** Un autor cuidadoso puede eludir cualquier indicio aislado. La fortaleza reside en el conjunto de registros independientes de un mismo hecho: falsificarlos todos de forma coherente a la vez (lista de agentes, entorno, indicadores, registro y contadores del espejo) es mucho más difícil.
- **Un cheat nativo sin JVMTI y sin attach** (lecturas y escrituras directas de memoria) deja muy pocos de los rastros que busca AgentScan.
- **El tiempo de ejecución** aumenta con el tamaño del heap: el análisis completo y el recorrido de metaspace leen toda la memoria del proceso.
- El escáner comprueba el proceso en el momento de ejecutarse. Los registros de eventos de la VM son circulares: las entradas más antiguas se sustituyen por las nuevas.

---

## Prueba positiva

`tests/positive/` contiene un objetivo y un agente Java de prueba: un transformador más `retransformClasses`. `run-test.cmd` inicia tres JVM: una sin agente, otra con `-javaagent` y otra con un agente conectado mediante `VirtualMachine.loadAgent`. Después ejecuta AgentScan en cada una. Se requiere JDK 21.

```bat
tests\positive\run-test.cmd
```

Resultado en JDK 21.0 (Windows 10):

| Proceso | CRITICAL | HIGH | MEDIUM | Código | Hallazgos principales |
|---|---|---|---|---|---|
| sin agente | 0 | 0 | 0 | 0 | — |
| `-javaagent` | 25 | 8 | 2 | 10 | registro del agente «instrument» con la ruta al jar y la marca «at startup», dos entornos JVMTI, `ClassFileLoadHook`, `InstrumentationImpl` y un transformador en el heap, indicador del agente en la copia de argumentos de la VM y en hsperfdata |
| attach | 27–29 | 8 | 2 | 10 | registro del agente con la marca «to a running VM», `Win32AttachOperation` con el comando `load`, una entrada en el registro `Classes redefined`, la operación `RedefineClasses` en el registro circular VM Operations y el contador de redefiniciones en el espejo de la clase `Target` |

Lo mismo en un juego real: Minecraft 1.21.10 (TLauncher, Fabric Loader 0.19.3, JDK 21), conjunto de trabajo de 1.4 GB.

| Proceso | CRITICAL | HIGH | MEDIUM | LOW | Tiempo | Código |
|---|---|---|---|---|---|---|
| juego limpio | 0 | 0 | 0 | 3 | 67 s | 0 |
| el mismo juego después de conectar el agente de prueba | 26 | 7 | 2 | 6 | 77 s | 10 |

Los tres hallazgos LOW del juego limpio son normales: cadenas aisladas de `InstrumentationImpl` (el descriptor del módulo `java.instrument` que la VM analiza al iniciarse) y «28 VM arguments are missing from the process command line»: TLauncher pasa esos argumentos en un archivo `@args`.

---

## Compilación

Se necesita .NET SDK 8.0 (solo en el equipo de compilación).

```bat
build.cmd
```

Se compilan dos variantes del mismo escáner:

| Archivo | Tamaño | Requisitos del equipo analizado |
|---|---|---|
| `dist\AgentScan.exe` | ~70 MB | ninguno: .NET 8 Runtime y WinForms están incluidos (independiente) |
| `dist\AgentScan-lite.exe` | ~1 MB | [.NET 8 Desktop Runtime x64](https://dotnet.microsoft.com/download/dotnet/8.0) |

Si `AgentScan-lite.exe` no encuentra .NET, el cargador de .NET muestra la ventana «You must install or update .NET to run this application». El botón «Download it now» lleva al sitio de Microsoft (`aka.ms/dotnet-core-applaunch`). Instala **.NET Desktop Runtime 8 (x64)**: ya incluye el .NET Runtime básico. Si solo está instalado el runtime básico, el siguiente inicio también solicitará Desktop Runtime.

Manualmente:

```bat
dotnet publish src -c Release -o out-full
dotnet publish src -c Release -o out-lite -p:SelfContained=false -p:EnableCompressionInSingleFile=false -p:PublishReadyToRun=false
```

ReadyToRun está desactivado deliberadamente en la variante lite. En la combinación «archivo único + sin runtime», un exe con ReadyToRun fallaba al iniciarse dentro de `coreclr.dll` (`0xC0000602`, verificado en .NET 8.0.27). Esto solo afecta al tiempo de inicio, no al propio escáner.

Estructura:

```
AgentScan/
  README.md            esta descripción (inglés)
  README.es.md         esta descripción (español)
  build.cmd            compilación: dist\AgentScan.exe completo y dist\AgentScan-lite.exe ligero
  src/
    Program.cs         análisis de argumentos, modo consola, ejecución del análisis y escritura de informes
    Gui/MainForm.cs    ventana: lista de procesos, barra de progreso y botones de informes
    Analysis/          comprobaciones y pipeline (Scanner.cs)
    Core/              lectura de procesos, mapa de memoria, VMStructs, heap de Java e índice de jars
    Native/            llamadas a ntdll/kernel32
    Report/            consola, HTML (EN/ES), TXT y JSON
  tests/positive/      objetivo y agente de prueba
```
