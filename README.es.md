# Samba Key

[English](README.md)

![License: MIT](https://img.shields.io/badge/license-MIT-blue)
![Status: experimental](https://img.shields.io/badge/status-experimental-orange)
![Security: not independently audited](https://img.shields.io/badge/security-not%20independently%20audited-lightgrey)
![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white)
![Docker](https://img.shields.io/badge/docker-supported-2496ED?logo=docker&logoColor=white)
![Samba](https://img.shields.io/badge/samba-standalone-lightgrey)
![Built with Qwen](https://img.shields.io/badge/built%20with-Qwen-6F42C1)
![Pi coding agent](https://img.shields.io/badge/agent-Pi-black)
![pi-here](https://img.shields.io/badge/launcher-pi--here-informational)
![Telegram](https://img.shields.io/badge/recovery-Telegram-26A5E4?logo=telegram&logoColor=white)


**Una pequeña página web autoalojada donde las personas que usan tu servidor de archivos Samba pueden cambiar su propia contraseña y pedir ayuda cuando la han olvidado.**

> **Estado:** experimental, con licencia MIT y **sin auditoría de seguridad independiente**. Pruébalo primero con una cuenta Samba descartable. Antes de confiar en él, lee [qué significa "probado" aquí](TESTING.md) (en inglés).

> **Cómo se hizo:** este proyecto se escribió con ayuda de IA, bajo mi dirección, revisión y pruebas. La programación la hizo un modelo **Qwen** que corre en local con [Ollama](https://ollama.com), manejado por el agente [Pi](https://pi.dev) y lanzado con mi propia herramienta, [pi-here](https://github.com/fedeblock/pi-here); consulté a un segundo modelo (Sonnet, de Anthropic) como asesor. Juzga el código por sus [pruebas](TESTING.md) (en inglés), no por quién lo escribió. Las [notas de desarrollo](docs/DESARROLLO.md) cuentan toda la historia: la configuración, cómo reproducirla y los problemas que encontramos.

## El problema

Imagina un servidor casero en un rincón del salón. Guarda las fotos de la familia, los papeles escaneados, una carpeta de música compartida y algunos trabajos de los chicos. Cada persona tiene su propia cuenta Samba, así que cada una ve las carpetas que le corresponden y nada más.

Un día alguien cambia de teléfono, olvida la clave o simplemente quiere otra. Samba no ofrece una pantalla amigable para eso. Las herramientas que cambian una contraseña (`smbpasswd`, `pdbedit`) viven en la línea de comandos del servidor, de modo que la pregunta es: *¿quién tiene que entrar al servidor para hacerlo?* Casi siempre, quien lo instaló, en el peor momento posible.

Es una situación muy común. Familias, grupos de amigos, pequeños estudios y equipos diminutos usan Samba porque es sencillo, gratuito y funciona con casi cualquier ordenador y teléfono. Lo que rara vez tienen es:

- un servicio de directorio como Active Directory o LDAP,
- un departamento de informática,
- ni una buena razón para dar acceso por consola al servidor solo para que alguien cambie una clave.

Samba Key cubre ese hueco. Da a cada persona una página privada en el navegador y deja las cuentas y los permisos de las carpetas donde ya están: en Samba.

## Qué hace

1. **Cambiar una contraseña que se conoce.** La persona escribe la clave actual y la nueva. El proceso web llama al cliente propio de Samba (`smbpasswd -r`) por la red, como lo haría alguien en una terminal. No lee la base de contraseñas de Samba y no tiene privilegios especiales.
2. **Pedir ayuda si se olvidó (opcional, desactivada por defecto).** La persona solicita la recuperación; la administración comprueba por otra vía que realmente es ella y aprueba la solicitud; entonces recibe por correo o Telegram un enlace de un solo uso y corta duración y elige una clave nueva. Detalles en el [diseño de la recuperación](RECOVERY-DESIGN.md) (en inglés).
3. **Mantener una pequeña agenda privada.** Un archivo opcional con nombre, correo y teléfono por cuenta, gestionado por quien administra. Registrar un contacto no activa la recuperación para esa persona.

La página está en español e inglés, se maneja con el teclado y se adapta a pantallas de teléfono.

### Cómo encajan las piezas

```
 navegador de la persona ──HTTPS──▶  página web de Samba Key ──cliente smbpasswd──▶  servidor Samba
 (móvil, portátil)                   (sin privilegios)                               (tus carpetas)
                                            │
                                            │ solo si la recuperación está activada
                                            ▼
                                      autoridad de recuperación ──▶ restablece solo cuentas autorizadas
                                      (aparte, con privilegios) ──▶ envía el enlace de un solo uso (correo / Telegram)
                                            ▲
                                            └── la administración aprueba cada solicitud
```

La decisión de diseño más importante es la separación: la página que usa la gente **solo** puede cambiar una contraseña que ya se conoce. Todo lo que podría cambiar la de otra persona ocurre en un componente aparte, que consulta una lista de cuentas autorizadas, exige la aprobación de la administración y no es accesible desde el contenedor de la web.

## Primeros pasos

Necesitas un servidor Linux con Docker, un servidor Samba accesible y una dirección HTTPS privada (por ejemplo con Tailscale). Después:

```sh
git clone https://github.com/fedeblock/samba-key.git
cd samba-key
docker build -t samba-key .
docker run -d --name samba-key --restart unless-stopped \
  --add-host host.docker.internal:host-gateway \
  -e SAMBA_SERVER=host.docker.internal \
  -p 127.0.0.1:18081:8080 samba-key
```

Eso arranca el portal de cambio de clave en la dirección local. **Todavía no está listo** para entregárselo a tu familia: faltan HTTPS, controles de acceso a la red y una configuración de Samba que acepte al contenedor. La [guía de instalación](docs/INSTALL.md) (en inglés) recorre cada paso y la recuperación opcional.

## Elige tu entorno

| Tienes… | Empieza por | Notas |
|---|---|---|
| Un servidor Linux con Docker y Samba | [Instalación, paso 1](docs/INSTALL.md) | La configuración que se ha probado. |
| Lo anterior, más recuperación de claves olvidadas | [Instalación, paso 2](docs/INSTALL.md) | Solo Linux con systemd; lee antes la [guía de operación](docs/OPERATIONS.md). |
| Samba en otra máquina de tu red | [Instalación, paso 1](docs/INSTALL.md) | Apunta `SAMBA_SERVER` a esa máquina. Solo sirve el cambio de clave: la recuperación necesita la autoridad en el mismo equipo que Samba. |
| Un Mac o un Windows como *cliente* | [Acceso de los clientes](docs/INSTALL.md#client-access-to-files) | Basta el navegador y el cliente VPN. |
| Un Mac, Windows (WSL2) o Linux para *desarrollar* | [TESTING](TESTING.md) | Python 3.11 o superior, entorno virtual y `unittest`. |
| Un NAS comercial, Active Directory o LDAP | sin validar | No des por hecho que funciona. |

## Compartir Samba con Tailscale: ¿para quién sirve?

Una red privada como [Tailscale](https://tailscale.com/) permite llegar a un servidor de casa sin publicar SMB (ni este portal) en internet. [Tailscale Serve](https://tailscale.com/docs/features/tailscale-serve) puede dar al portal una dirección HTTPS privada, y [compartir dispositivos](https://tailscale.com/docs/features/sharing) permite invitar a personas ajenas a tu red. Cambia bastante según quiénes sean "todos":

| | Familia | Grupo de amigos | Equipo de trabajo pequeño |
|---|---|---|---|
| **Qué ayuda** | Ya confían en ti; pocos dispositivos; es fácil de explicar ("instala esta app y abre esta dirección"). | Compartir el dispositivo permite que un amigo llegue solo a tu servidor desde su propia cuenta de Tailscale, sin entrar en tu red. | Cuentas Samba individuales y reglas de acceso de Tailscale dan una configuración razonable de mínimo privilegio sin comprar un producto de servidor. |
| **Qué se complica** | Te conviertes en el servicio técnico, que es justo lo que Samba Key reduce. Abuelos y niños necesitan una app VPN instalada. | La confianza es menor: importan las cuentas y carpetas separadas, y dar de baja a alguien implica retirar tanto el acceso al dispositivo como su cuenta Samba. | Samba independiente no tiene inicio de sesión único ni directorio central: las cuentas se gestionan en cada servidor. Disponibilidad, copias y "¿quién administra cuando no estás?" pasan a ser preguntas reales. |
| **Uso típico** | Una carpeta por persona y una o dos compartidas. | Un recurso común para el grupo y carpetas privadas por persona. | Recursos por proyecto, una persona administradora documentada y copias probadas. |

Lo que vale para los tres casos:

- **Todos necesitan el cliente VPN** (o una invitación de dispositivo aceptada). Televisores, consolas, algunos portátiles gestionados por una empresa y ciertas redes restringidas a menudo no pueden usarlo. Abrir el servidor al público para ellos es otra decisión, y nunca debería incluir SMB ni este portal.
- **La VPN no es autenticación.** Las contraseñas y permisos de Samba siguen decidiendo quién abre qué. Prueba por separado la política de acceso de Tailscale, el cortafuegos y los permisos de Samba, y hazlo desde una cuenta invitada real: un dispositivo compartido y un miembro de la red se comportan distinto.
- **La VPN no es una copia de seguridad.** El servidor tiene que estar encendido, actualizado y respaldado. La velocidad depende de si los equipos se conectan directamente o mediante un repetidor, y de la subida de tu conexión doméstica.
- **Las claves guardadas se quedan.** Tras cambiar una contraseña, teléfonos y portátiles con la anterior guardada pueden seguir intentándolo y, en el peor caso, bloquear la cuenta. Pide a cada persona que actualice su conexión guardada.
- **Es buena opción cuando** el grupo es pequeño, hay confianza y alguien está dispuesto a administrar un servidor Linux. **Piénsalo dos veces cuando** necesites auditoría, gestión central de usuarios, cumplimiento normativo o disponibilidad garantizada: ahí conviene una base gestionada o con directorio.

## Seguridad, en pocas palabras

- Usa el portal solo con **HTTPS en una red privada y con acceso controlado**. No lo publiques, ni a SMB, directamente en internet.
- **La recuperación está desactivada por defecto** y la recuperación automática no está implementada a propósito. Cuando se activa, la administración aprueba cada solicitud.
- El contenedor web nunca recibe root, sudo sin restricciones, el socket de Docker, el socket de administración ni la base de contraseñas de Samba.
- Un límite que conviene conocer: si la propia página web estuviera comprometida mientras alguien restablece su clave, podría capturar el enlace y la contraseña nueva que se escriben en ella. El diseño reduce ese riesgo, no lo elimina. La [guía de operación](docs/OPERATIONS.md#13-residual-risks-accepted-mitigated-operationally) enumera los riesgos residuales.
- ¿Encontraste un problema? Lee [SECURITY.md](SECURITY.md) y avisa en privado.

## Algunos términos

- **Samba / SMB**: el protocolo de archivos compartidos que Windows, macOS, Linux, iOS y Android usan para abrir carpetas de un servidor.
- **`smbpasswd`**: el comando de Samba para cambiar una contraseña.
- **Samba independiente**: un servidor Samba con su propia lista de usuarios, que no consulta Active Directory ni LDAP.
- **Tailnet**: tu red privada dentro de Tailscale.
- **Autoridad**: el pequeño servicio con privilegios que, en el modo de recuperación, puede restablecer claves de las cuentas que hayas autorizado.

## Dónde seguir

| Si quieres… | Lee |
|---|---|
| Instalarlo en distintos entornos | [docs/INSTALL.md](docs/INSTALL.md) (inglés) |
| Activar la recuperación y entender cada ajuste | [docs/OPERATIONS.md](docs/OPERATIONS.md) (inglés) |
| Entender por qué la recuperación se diseñó así | [RECOVERY-DESIGN.md](RECOVERY-DESIGN.md) (inglés) |
| Ver qué se ha probado y qué no | [TESTING.md](TESTING.md) (inglés) |
| Ver lo que falta | [TODO.md](TODO.md) (inglés) |
| Configurar el relay de correo y el bot de Telegram para la recuperación | [docs/NOTIFICATIONS.md](docs/NOTIFICATIONS.md) (inglés) |
| Saber cómo se construyó, con Qwen local, Pi y pi-here | [docs/DESARROLLO.md](docs/DESARROLLO.md) |

## Cómo se construyó

Construí Samba Key con un modelo **Qwen** servido en local y manejado por el agente **Pi**, que lanzo con mi propia herramienta, [pi-here](https://github.com/fedeblock/pi-here), y consulté a un segundo modelo como asesor cuando quise otra opinión. Las [notas de desarrollo](docs/DESARROLLO.md) explican la configuración, cómo reproducirla y los problemas del camino: sesiones larguísimas, compactaciones, un fallo del ejecutor en la GPU y los errores que detectaron las revisiones y las pruebas en un servidor real. Ni Qwen, ni Pi, ni pi-here hacen falta para instalar o usar Samba Key; el código debe juzgarse por su implementación y por las pruebas, no por el modelo que lo escribió.

## Licencia

[MIT](LICENSE).
