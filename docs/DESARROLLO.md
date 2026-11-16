# Cómo construí Samba Key con Qwen, Pi y pi-here

[English](DEVELOPMENT.md)

Esta es la historia de cómo se hizo Samba Key, escrita para dos tipos de lectores: quienes sienten curiosidad por trabajar con un modelo de programación **local** y quienes quieren repetir la configuración. También cuenta, sin maquillaje, lo que salió mal por el camino. **No** necesitas ninguna de estas herramientas para instalar o usar Samba Key.

## Por qué existe el proyecto

Samba Key empezó en casa. Compartimos carpetas en un servidor Samba y, cuando alguien olvida su clave, cambiarla le toca a quien administra el servidor. Quería que cada persona pudiera cambiar su contraseña con facilidad y pedir ayuda si no recordaba la anterior. Muchas otras familias, grupos de amigos y equipos pequeños deben de tener la misma necesidad, así que el objetivo pasó a ser una herramienta pequeña y reutilizable, no algo solo para mi casa. [El README](../README.es.md) describe el problema con más detalle.

También era una excusa para probar otra cosa: un flujo de trabajo con un modelo que corre en mi propio ordenador.

## Las herramientas, de un vistazo

| Pieza | Qué es | Para qué la usé |
|---|---|---|
| [Pi](https://pi.dev) | Un agente de programación ligero y extensible para la terminal. | Una "hoja en blanco" sobre la que construir, en lugar de un entorno más pesado. |
| [Ollama](https://ollama.com) | Un programa que descarga y sirve modelos de lenguaje en local. | Ejecuta el modelo en mi equipo; el código no sale de la máquina. |
| **Qwen 3.8 27B** | El modelo que hizo la mayor parte del trabajo. Los registros de sesión lo identifican como `ollama/qwen3.8:27b`; es el nombre que informó mi instalación, así que comprueba cómo lo llama tu Ollama. | Un modelo local capaz, con esfuerzo de razonamiento *medio*. |
| [pi-here](https://github.com/fedeblock/pi-here) | Un lanzador que escribí para iniciar Pi en una carpeta con el modelo, el razonamiento, las extensiones y las habilidades elegidos. | Ver la sección siguiente. |
| Extensiones y habilidades | Control de permisos, rutas protegidas, [Superpowers](https://www.npmjs.com/package/@tsubus/pi-superpowers) y habilidades para planificar, programar con pruebas, depurar y verificar. | Barandillas y buenos hábitos para un modelo más pequeño que los alojados en la nube. |
| Un asesor | Una herramienta que permite al modelo de trabajo pedir opinión a otro modelo más potente. Usé **Sonnet 5.5 de Anthropic** mediante su API. | Una segunda mirada sobre diseño y seguridad. |

Usar un modelo local tiene ventajas e inconvenientes reales. **A favor:** el código y la conversación se quedan en mi equipo, no hay factura por token y funciona sin conexión. **En contra:** es más lento y menos capaz que los grandes modelos alojados, un contexto largo cuesta tiempo de verdad y todo el experimento exige un ordenador bastante potente. El asesor fue una vía de escape para las preguntas más difíciles; es una API opcional y de pago que *sí* envía la conversación a un tercero, por eso configuré su clave aparte y la mantuve fuera del repositorio.

## Cómo configuré Pi con pi-here

### Por qué un lanzador

Cada herramienta, extensión y habilidad que carga Pi añade texto al mensaje de sistema. Con un modelo local, más texto significa procesar más despacio, y cambiar el conjunto invalida la caché del modelo. Por eso la decisión de *qué cargar* se toma al arrancar y depende del trabajo: un arreglo rápido, una sesión larga de construcción, una revisión de solo lectura. `pi-here` hace visible esa elección: lo ejecutas en la carpeta del proyecto, te muestra el comando exacto que va a lanzar y pulsas Enter.

### Instalación en macOS o Linux

`pi-here` funciona en macOS y Linux; en Windows no está probado. Su [README](https://github.com/fedeblock/pi-here#install) es la referencia vigente de requisitos.

1. **Instala Ollama** desde [ollama.com](https://ollama.com) y descarga un modelo que tu equipo pueda mover. Mira el tamaño del modelo en su página de Ollama antes de bajarlo: uno de 27B necesita mucha memoria.
2. **Instala Pi** siguiendo las instrucciones de [pi.dev](https://pi.dev).
3. **Instala Node.js** 20.12 o superior y después pi-here desde un clon:

   ```sh
   git clone https://github.com/fedeblock/pi-here.git
   cd pi-here
   npm install
   npm link            # deja `pi-here` en el PATH
   pi-here --version   # comprobación
   ```

4. **Instala las extensiones o habilidades que quieras**, con el propio Pi; por ejemplo `pi install npm:@tsubus/pi-superpowers`. *Lee antes el código de cada paquete: las extensiones se ejecutan con los permisos de tu usuario.*
5. En la carpeta del proyecto, ejecuta `pi-here config` para elegir qué carga cada perfil y `pi-here --dry-run` para ver el comando que lanzará.

### Un perfil

Esto ilustra la *forma* de un perfil de pi-here (`~/.config/pi-here/config.json`), no la configuración de Samba Key. Las rutas son marcadores para extensiones y habilidades que hayas instalado y revisado tú:

```json
{
  "launcher": "ollama",
  "presets": {
    "samba-example": {
      "model": "qwen3.8:27b",
      "thinking": "medium",
      "extensions": {"mode": "only", "load": ["/path/to/reviewed-extension.ts"]},
      "skills": {"mode": "only", "load": ["/path/to/reviewed-skill/SKILL.md"]}
    }
  }
}
```

Con un perfil así, `pi-here --dry-run` imprime algo con esta forma:

```
ollama launch pi --model qwen3.8:27b -- --thinking medium --no-extensions --extension /path/to/reviewed-extension.ts --no-skills ...
```

Dos aclaraciones. Primero: un perfil facilita el arranque, pero **no es una barrera de seguridad**; los permisos y la protección de rutas se gestionan aparte. Segundo: el nombre del modelo de arriba es el de mi instalación; el tuyo puede ser otro.

## Cómo fue el trabajo

Yo marcaba las prioridades, leía las propuestas y decidía cómo seguir. Qwen se ocupó de buena parte de la implementación y la documentación, y las habilidades que cargué lo empujaban a trabajar en pasos pequeños: escribir una prueba, hacerla pasar y ejecutar todo. Cuando quería otra perspectiva sobre una decisión de diseño o de seguridad, consultaba a Sonnet. En seis días (del 11 al 16 de noviembre) el trabajo llevó 64 commits, más o menos en este orden:

1. **Una página para cambiar la clave** en español e inglés, que llama al cliente propio de Samba y no exige acceso administrativo al servidor.
2. **Reforzar ese flujo**, con un arreglo para que la clave *actual* no tenga que cumplir la regla de longitud de la clave *nueva*.
3. **Recuperación de claves olvidadas**, que pasó por un rediseño: primero un portal que hacía más de lo debido, y después una *autoridad* privilegiada y separada que es dueña de los canales de contacto y del envío.
4. **Pruebas contra un Samba real**: contenedores descartables para el cambio de clave, el restablecimiento, la separación de privilegios y la cadena completa.
5. **Ensayos en un servidor real** con una cuenta de prueba, correo real y un bot real de Telegram.
6. **Documentación**, una y otra vez, a medida que el código dejaba de coincidir con ella.

Dos archivos del repositorio existen por esta forma de trabajar: [AGENTS.md](../AGENTS.md) (las reglas que debe seguir cualquier agente: privacidad, recuperación desactivada por defecto, cuentas de prueba descartables, pruebas de casos de fallo) y [HANDOFF.md](../HANDOFF.md) (el estado resumido del proyecto para quien, o lo que, lo retome). Más abajo aparecen como respuesta a distintos problemas.

## Las sesiones guardadas

Se revisaron tres exportaciones de sesiones de Pi. Las cifras describen solo esas exportaciones; mensajes, resultados de herramientas y compactaciones miden cosas distintas y ninguna mide la calidad. Las exportaciones contienen contexto privado y no se publican.

| Sesión | Actividad registrada | Qué pasó |
|---|---|---|
| Primera | 334 mensajes, 156 resultados de herramientas, sin compactaciones | Se reforzó el cambio de clave, se corrigió la comprobación de longitud de la clave actual y se mantuvo desactivada la recuperación incompleta. |
| Segunda | 1.762 mensajes, 878 resultados de herramientas (8 llamadas al asesor), 4 compactaciones | La sesión larga de la recuperación. La exportación termina durante la implementación e incluye un fallo del ejecutor local. |
| Tercera | 992 mensajes, 501 resultados de herramientas (6 llamadas al asesor), 1 compactación | Continuaron la implementación, las revisiones y las pruebas. La exportación termina durante tareas de seguimiento, así que por sí sola no demuestra que las fases posteriores se completaran. |

## Problemas que encontramos

Esta es la parte que me habría gustado leer antes de empezar. Cada punto cuenta qué pasó, qué me enseñó y qué hago ahora.

### 1. Sesiones largas, compactación y empezar de nuevo

**Qué pasó.** Las sesiones crecieron. Una acumuló unos **100 millones de tokens de entrada**, casi todos servidos desde caché. Es la suma de muchísimas llamadas, no el tamaño de una única ventana de contexto. Cuando el contexto se llenaba, Pi lo *compactaba*: resumía la conversación anterior y seguía. La segunda sesión se compactó cuatro veces.

**Qué me enseñó.** Un resumen es un resumen. Tras una compactación, el modelo podía perder una decisión, una restricción o una prueba pendiente, y luego rehacer o contradecir con seguridad lo ya hecho. Además, los historiales largos cuestan tiempo y hacen más difícil detectar errores.

**Qué hago ahora.** Guardo lo importante *fuera* de la conversación: [HANDOFF.md](../HANDOFF.md) para el estado del proyecto, [AGENTS.md](../AGENTS.md) para las reglas y git para el historial. Cuando una sesión pesa demasiado, abro otra nueva y empiezo con: el objetivo, la rama, las decisiones ya tomadas, lo que queda a medias y el siguiente paso seguro. Después dejo que el agente lea el repositorio, no su recuerdo del repositorio.

### 2. El fallo del ejecutor en la GPU

**Qué pasó.** El ejecutor Ollama/MLX de mi Mac se detuvo con un error de Metal identificado como `Impacting Interactivity`. La sesión en curso quedó interrumpida.

**Qué me enseñó.** No pude atribuirlo a una única causa. Un modelo más pequeño, menos contexto o menos carga gráfica *podrían* ayudar a diagnosticar un fallo así, pero no he comprobado ninguna de esas ideas y no afirmo haberlo resuelto. Lo que sí ayudó fue no depender de la sesión: con un traspaso claro, una nueva retomaba el trabajo en pocos minutos.

### 3. Pruebas que pasan mientras la realidad falla

**Qué pasó.** Buena parte de las primeras pruebas usaba sustitutos de Samba, del correo y de Telegram. Permiten avanzar rápido, pero solo demuestran que el código hace lo que *yo creo* que hace el mundo exterior. El caso más claro: la primera versión del restablecimiento enviaba la clave nueva por una tubería asociada a un descriptor de archivo, porque el diseño suponía que `smbpasswd` la leería de allí. El `smbpasswd` real no lo hace: `smbpasswd -s` lee la clave nueva, dos veces, desde la entrada estándar. Las pruebas unitarias estaban en verde y el restablecimiento real habría fallado.

**Qué me enseñó.** Las pruebas con simulaciones responden a "¿es coherente mi lógica?", no a "¿coincide la realidad?". Las revisiones y los ensayos con un Samba real descartable encontraron una serie de problemas que las simulaciones no podían detectar: el transporte de la clave descrito arriba, partes de la interfaz web que no estaban conectadas al nuevo servicio, una elección errónea de canal y transacciones de SQLite que mantenían un bloqueo de escritura más tiempo del debido.

**Qué hago ahora.** Todo lo que cruza una frontera (Samba, SMTP, Telegram, los permisos de usuarios y sockets del sistema operativo) recibe al menos una prueba contra el componente real en un contenedor descartable, y anoto en [TESTING.md](../TESTING.md) (en inglés) de qué capa procede cada resultado.

### 4. Errores que encontraron las revisiones

Cuatro defectos aparecieron en rondas de revisión y se corrigieron uno a uno, cada uno con una prueba que falla sin el arreglo:

- **El sondeo de Telegram giraba en vacío.** Una "espera" que no esperaba hacía que se machacara la API en un bucle apretado, y una caída del servicio se veía igual que "no hay mensajes". Ahora hace pausas, puede interrumpirse y espera más tras los fallos.
- **Cambiar un canal no anulaba un enlace ya enviado.** Si la administración revocaba un canal de contacto, un enlace ya emitido seguía funcionando hasta caducar. Ahora cualquier alta, cambio o baja invalida las solicitudes pendientes, aprobadas *y* emitidas de la cuenta.
- **Un directorio de datos volátil.** El registro de la recuperación podía acabar en `/run` o `/tmp`, que no sobreviven a un reinicio. La autoridad ahora se niega a arrancar así.
- **Ajustes que nunca llegaban al proceso.** Varias opciones de configuración se leían pero no se transmitían, de modo que el portal aplicaba una política y la autoridad otra. Una prueba global comprueba ahora que cada ajuste se utiliza de verdad.

### 5. Pruebas que no probaban nada

**Qué pasó.** Una prueba de seguridad puede "pasar" porque lo que debía prohibir nunca llegó a ocurrir. Una prueba que dice "el portal no puede aprobar una solicitud" no vale nada si la solicitud ni siquiera estaba pendiente. Varias rondas de revisión de las pruebas de separación de privilegios las empujaron de "no pasó nada malo" hacia pruebas de que la acción se intentó de verdad y se rechazó de verdad.

**Qué hago ahora.** Las pruebas de seguridad tienen que poder fallar. Las de separación de privilegios y de la cadena completa incluyen comprobaciones *no vacías* (se muestra que la solicitud está pendiente y sigue pendiente después) y controles negativos que están pensados para fallar; [TESTING.md](../TESTING.md) indica cuáles.

### 6. La documentación se desfasa

**Qué pasó.** Los documentos del proyecto discrepaban del código una y otra vez: un número de pruebas obsoleto, notas de "aún no probado" sobre cosas que ya se habían probado y afirmaciones que iban más allá de la evidencia. Varias rondas de revisión las corrigieron.

**Qué hago ahora.** Los documentos dicen *qué se probó, en qué, y qué no*, y evitan las promesas. El estado honesto ("experimental, sin auditoría independiente") aparece en el README, en las notas de seguridad y en la guía de operación.

### 7. Confiar en el asesor

Se consultó al asesor **14 veces** en las dos sesiones posteriores. Sus respuestas fueron *propuestas* útiles sobre diseño y seguridad, pero hubo que contrastarlas con el código, las pruebas y el comportamiento real, como las de cualquiera. No es una auditoría de seguridad y el proyecto no la reclama.

## Consejos prácticos si quieres probarlo

- **Empieza en pequeño y mantén un archivo de traspaso.** Anota en un archivo del repositorio el objetivo, las reglas y el siguiente paso.
- **Haz que el agente ejecute las pruebas** y lee tú mismo la salida.
- **Prueba las fronteras reales** con contenedores descartables, nunca con cuentas reales.
- **Trata la compactación como una pérdida de información.** Si una decisión importa, que quede en un archivo.
- **Mantén pequeño el conjunto de herramientas.** Más extensiones significan un mensaje más pesado y un modelo local más lento.
- **No pongas secretos en mensajes, perfiles ni repositorios.** Usa una configuración aparte para las claves de API.

## Lo que este proceso no demuestra

Pi, Qwen y el asesor **no** sustituyen a una revisión. Samba Key debe juzgarse por su código y por sus [pruebas](../TESTING.md), no por el modelo que lo escribió. Sigue siendo experimental y no ha tenido una auditoría independiente. Las transcripciones completas pueden contener rutas, identificadores, datos de contacto o credenciales, por eso se conservan fuera del repositorio; si publicas registros o informes de errores propios, revísalos y límpialos antes.
