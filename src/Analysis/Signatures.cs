using System.Text;
using System.Text.Json;
using AgentScan.Report;

namespace AgentScan.Analysis;

internal enum SigScope
{
    Any,
    NonImage,
    PrivateOnly,
    PrivateExec,
}

internal sealed class Signature
{
    public required string Name { get; init; }
    public required string Category { get; init; }
    public required string Text { get; init; }
    public Severity Severity { get; init; } = Severity.Medium;
    public SigScope Scope { get; init; } = SigScope.Any;
    public bool Utf16 { get; init; } = true;

    public bool WholeWord { get; init; } = true;

    public string? Note { get; init; }
}

internal static class Signatures
{
    public static List<Signature> Default()
    {
        var s = new List<Signature>();

        void Inj(string name, string txt, Severity sev, SigScope scope, string note)
            => s.Add(new Signature
            {
                Name = name, Category = L("Injection artifact", "Artefacto de inyección"), Text = txt,
                Severity = sev, Scope = scope, Note = note
            });

        Inj(L("JVMTI Agent_OnAttach outside modules", "JVMTI Agent_OnAttach fuera de módulos"), "Agent_OnAttach", Severity.High, SigScope.PrivateExec,
            L("Entry point string of a JVMTI agent in private executable memory. jvm.dll always has it, but in foreign memory only agent/injector code does.", "Cadena del punto de entrada de un agente JVMTI en memoria privada ejecutable. jvm.dll siempre la tiene, pero en memoria ajena solo la tiene el código de un agente o inyector."));
        Inj(L("JVMTI Agent_OnUnload outside modules", "JVMTI Agent_OnUnload fuera de módulos"), "Agent_OnUnload", Severity.High, SigScope.PrivateExec,
            L("JVMTI agent unload point outside loaded modules.", "Punto de descarga de un agente JVMTI fuera de los módulos cargados."));
        Inj("JPLISAgent", "JPLISAgent", Severity.High, SigScope.PrivateOnly,
            L("Internal name of the java.lang.instrument agent (instrument.dll). Appears when -javaagent is loaded or on dynamic attach.", "Nombre interno del agente java.lang.instrument (instrument.dll). Aparece al cargar -javaagent o en un attach dinámico."));
        Inj("attach pipe", @"\\.\pipe\javatool", Severity.Critical, SigScope.PrivateOnly,
            L("Named pipe of the Dynamic Attach mechanism (VirtualMachine.attach). The pipe name is passed to the VM when an agent attaches to it.", "Tubería con nombre del mecanismo Dynamic Attach (VirtualMachine.attach). El nombre de la tubería se pasa a la VM cuando un agente se conecta a ella."));
        Inj("VirtualMachine.loadAgent", "loadAgentLibrary", Severity.High, SigScope.PrivateOnly,
            L("Call that attaches a native agent library to a live JVM.", "Llamada que conecta una biblioteca de agente nativa a una JVM en ejecución."));
        Inj("JNI_GetCreatedJavaVMs", "JNI_GetCreatedJavaVMs", Severity.High, SigScope.PrivateExec,
            L("Looking up the JavaVM pointer from native code — the typical first step of a native cheat working through JNI.", "Búsqueda del puntero JavaVM desde código nativo: el primer paso típico de un cheat nativo que trabaja mediante JNI."));
        Inj("AttachCurrentThread", "AttachCurrentThread", Severity.High, SigScope.PrivateExec,
            L("Attaching a native thread to the JVM from code outside modules.", "Conexión de un hilo nativo a la JVM desde código fuera de módulos."));

        void Jvmti(string txt, Severity sev = Severity.High)
            => s.Add(new Signature
            {
                Name = $"JVMTI: {txt}", Category = L("JVMTI agent artifact", "Artefacto de agente JVMTI"), Text = txt,
                Severity = sev, Scope = SigScope.PrivateExec,
                Note = L("JVMTI function name in private executable memory. Inside jvm.dll such strings always exist, but in foreign memory they appear only in agent code that calls these functions.", "Nombre de función JVMTI en memoria privada ejecutable. Dentro de jvm.dll estas cadenas siempre existen, pero en memoria ajena solo aparecen en el código de un agente que llama a estas funciones.")
            });

        Jvmti("RetransformClasses");
        Jvmti("RedefineClasses");
        Jvmti("GetLoadedClasses");
        Jvmti("SetJNIFunctionTable", Severity.Critical);
        Jvmti("SetEventNotificationMode");
        Jvmti("AddCapabilities");
        Jvmti("IterateOverInstancesOfClass");
        Jvmti("GetObjectsWithTags");
        Jvmti("FollowReferences");
        Jvmti("DisposeEnvironment");
        Jvmti("GetJNIFunctionTable", Severity.Critical);

        Inj("appendToSystemClassLoaderSearch", "appendToSystemClassLoaderSearch",
            Severity.Critical, SigScope.PrivateOnly,
            L("Instrumentation method that adds an arbitrary jar to the system class loader search. It is the standard way to slip Java cheat code into the JVM after the game has started.", "Método de Instrumentation que añade un jar arbitrario a la búsqueda del cargador de clases del sistema. Es la forma estándar de colar código de un cheat de Java en la JVM después de iniciar el juego."));
        Inj("appendToBootstrapClassLoaderSearch", "appendToBootstrapClassLoaderSearch",
            Severity.Critical, SigScope.PrivateOnly, "");
        Inj("redefineModule", "redefineModule", Severity.Medium, SigScope.PrivateOnly, "");
        Inj("ByteBuddy", "net/bytebuddy/agent", Severity.High, SigScope.PrivateOnly,
            L("Byte Buddy Agent — a library used to attach a Java agent to its own JVM (self-attach). The Minecraft client does not contain it.", "Byte Buddy Agent: biblioteca usada para conectar un agente Java a su propia JVM (self-attach). El cliente de Minecraft no la contiene."));
        Inj("Javassist", "javassist/ClassPool", Severity.Medium, SigScope.PrivateOnly,
            L("Runtime bytecode generation library.", "Biblioteca de generación de bytecode en tiempo de ejecución."));
        Inj("Unsafe.defineAnonymousClass", "defineAnonymousClass", Severity.Low,
            SigScope.PrivateOnly, "");

        string InstrNote =
            L("The string belongs to the java.lang.instrument mechanism. Single occurrences also happen in a clean JVM (class names of the java.instrument module are parsed at startup). What matters is the number of occurrences and, above all, the presence of the bytecode of these classes — see the residual JVM state section.", "La cadena pertenece al mecanismo java.lang.instrument. Las apariciones aisladas también ocurren en una JVM limpia (los nombres de clases del módulo java.instrument se analizan al arrancar). Lo que importa es el número de apariciones y, sobre todo, la presencia del bytecode de estas clases: vea la sección del estado residual de la JVM.");

        Inj("sun.instrument.InstrumentationImpl", "sun/instrument/InstrumentationImpl",
            Severity.Low, SigScope.PrivateOnly, InstrNote);
        Inj(L("sun.instrument.InstrumentationImpl (dotted notation)", "sun.instrument.InstrumentationImpl (notación con puntos)"),
            "sun.instrument.InstrumentationImpl", Severity.Low, SigScope.PrivateOnly, InstrNote);
        Inj("TransformerManager", "TransformerManager", Severity.Low, SigScope.PrivateOnly,
            L("Manager of registered ClassFileTransformers. ", "Gestor de ClassFileTransformer registrados. ") + InstrNote);
        Inj(L("agent premain", "premain del agente"), "loadClassAndCallPremain", Severity.High,
            SigScope.PrivateOnly,
            L("Internal instrument.dll function that runs the agent premain. Unlike class names, this string belongs to the native instrument.dll library, which is loaded only together with an agent.", "Función interna de instrument.dll que ejecuta el premain del agente. A diferencia de los nombres de clases, esta cadena pertenece a la biblioteca nativa instrument.dll, que solo se carga junto con un agente."));
        Inj("agentmain", "loadClassAndCallAgentmain", Severity.High, SigScope.PrivateOnly,
            L("Internal instrument.dll function that runs the agentmain of a dynamically attached agent.", "Función interna de instrument.dll que ejecuta el agentmain de un agente conectado dinámicamente."));
        Inj("addTransformer", "addTransformer", Severity.Low, SigScope.PrivateOnly,
            L("ClassFileTransformer registration — on-the-fly class bytecode replacement. ", "Registro de ClassFileTransformer: sustitución del bytecode de clases en caliente. ") + InstrNote);
        Inj("retransformClasses", "retransformClasses", Severity.Low, SigScope.PrivateOnly,
            L("Retransformation of already loaded game classes. ", "Retransformación de clases del juego ya cargadas. ") + InstrNote);
        Inj("ByteBuddy", "net/bytebuddy/", Severity.High, SigScope.PrivateOnly,
            L("Byte Buddy — a bytecode generation library often used by Java cheats for self-attach and method replacement.", "Byte Buddy: biblioteca de generación de bytecode usada a menudo por cheats de Java para self-attach y sustitución de métodos."));
        Inj("Javassist", "javassist/", Severity.Medium, SigScope.PrivateOnly, "");
        Inj(L("Mixin outside Fabric", "Mixin fuera de Fabric"), "org/spongepowered/asm/mixin/transformer", Severity.Info,
            SigScope.PrivateOnly,
            L("Mixin is part of Fabric and Forge — not evidence on its own.", "Mixin forma parte de Fabric y Forge: no es una prueba por sí solo."));

        return s;
    }

    public static List<Signature> Load(string? extraPath)
    {
        var list = Default();
        string path = extraPath ?? Path.Combine(AppContext.BaseDirectory, "signatures.json");
        if (!File.Exists(path)) return list;
        try
        {
            var json = File.ReadAllText(path);
            var extra = JsonSerializer.Deserialize<List<Signature>>(json,
                new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true,
                    ReadCommentHandling = JsonCommentHandling.Skip,
                    AllowTrailingCommas = true,
                });
            if (extra is not null) list.AddRange(extra);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"signatures.json not loaded: {ex.Message}");
        }
        return list;
    }

    public static byte[] Ascii(string s) => Encoding.ASCII.GetBytes(s);
    public static byte[] Utf16(string s) => Encoding.Unicode.GetBytes(s);
}
