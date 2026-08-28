# VulnRadar — Backend

Backend de **VulnRadar**, una plataforma web para documentar, consultar y verificar vulnerabilidades de seguridad en aplicaciones web. Desarrollado como Trabajo de Fin de Máster (TFM).

Este repositorio contiene la API REST y la lógica de negocio de la aplicación. El frontend vive en un repositorio independiente: [tfm-web](https://github.com/Alberto2908/tfm-web).

## Características

- **Catálogo de vulnerabilidades**: CRUD completo con filtrado (texto, severidad, categoría, rango de fechas) y paginación en servidor.
- **Importación real desde la NVD**: importación masiva del histórico de la [National Vulnerability Database](https://nvd.nist.gov/) e importación incremental bajo demanda de los CVE más recientes.
- **Agente de IA**: agente unificado, basado en la API de [Google Gemini](https://ai.google.dev/), que descubre, verifica, sanea y enriquece vulnerabilidades del catálogo — incluida la extracción de hallazgos a partir de documentación externa (informes de pentesting, documentación de detección) subida por un administrador.
- **Exportación multiformato**: del catálogo y del dashboard en CSV, JSON, XML y PDF.
- **Dashboard**: endpoint de estadísticas agregadas del catálogo para el frontend.
- **Autenticación y autorización**: sesión de servidor con [Spring Security](https://spring.io/projects/spring-security), roles de usuario y administrador.

## Tecnologías

- [Java 21](https://openjdk.org/)
- [Spring Boot 4](https://spring.io/projects/spring-boot)
- [Spring Security](https://spring.io/projects/spring-security)
- [Spring Data MongoDB](https://spring.io/projects/spring-data-mongodb) + [MongoDB Atlas](https://www.mongodb.com/atlas)
- [Maven](https://maven.apache.org/)
- [OpenPDF](https://github.com/LibrePDF/OpenPDF) — generación de informes PDF

## Requisitos previos

- JDK 21
- Una base de datos MongoDB (por ejemplo, un clúster gratuito de MongoDB Atlas)
- (Opcional) Una API key de [Google Gemini](https://ai.google.dev/) para activar el agente de IA
- (Opcional) Una API key de la [NVD](https://nvd.nist.gov/developers/request-an-api-key) para la importación de vulnerabilidades

## Configuración

La aplicación se configura por completo mediante variables de entorno (ver `src/main/resources/application.properties` para la lista completa y sus valores por defecto). Las imprescindibles para arrancar en local:

```
MONGODB_URI=mongodb+srv://usuario:contraseña@cluster.mongodb.net/nombre-bd
```

Variables opcionales relevantes:

| Variable | Descripción | Por defecto |
|---|---|---|
| `AGENTS_ENABLED` | Activa el agente de IA | `false` |
| `GEMINI_API_KEY` | API key de Google Gemini (necesaria si `AGENTS_ENABLED=true`) | — |
| `GEMINI_MODEL` | Modelo de Gemini a usar | `gemini-3.6-flash` |
| `NVD_API_KEY` | API key de la NVD, para la importación de CVE | — |
| `IMPORT_CVE_ENABLED` | Ejecuta la importación masiva puntual de CVE al arrancar | `false` |
| `SESSION_COOKIE_SAME_SITE` / `SESSION_COOKIE_SECURE` | Atributos de la cookie de sesión; deben ir a `none` / `true` cuando el frontend y el backend están en dominios distintos | `lax` / `false` |

## Ejecución en local

`main` solo contiene este README; el código vive en `develop`.

```bash
git checkout develop
./mvnw spring-boot:run
```

La API queda disponible en `http://localhost:8080`.

## Despliegue

El proyecto incluye un `Dockerfile` para desplegarse en cualquier proveedor compatible con contenedores. Incorpora además un endpoint de salud (`GET /health`) y un mecanismo de mantenimiento de actividad pensado para el nivel gratuito de [Render](https://render.com/).

## Ramas

- `main`: rama base del repositorio.
- `develop`: desarrollo activo, con historial de commits granular por funcionalidad.
- `production`: réplica de `develop` una vez probado; conectada a Render para el despliegue automático.

## Autor

Alberto Cabello Lasheras
