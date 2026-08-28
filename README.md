# OsintPro - Ethical OSINT Project

Herramientas de Open Source Intelligence (OSINT) para investigación ética en ciberseguridad, análisis de criptomonedas, detección de phishing y prevención de fraudes.

## Características

- **Análisis Crypto**: Verificación de wallets Ethereum y Bitcoin
- **Detección de Phishing**: Análisis de URLs, emails y dominios sospechosos
- **Análisis de Dominios**: WHOIS, SSL, reputación de dominios
- **Monitoreo de Brechas**: Verificación de emails en bases de datos de filtraciones
- **Análisis de Proyectos**: Due diligence para proyectos crypto

## Instalación

```bash
# Clonar repositorio
git clone https://github.com/YavlPro/OsintPro.git
cd OsintPro

# Crear entorno virtual
python3 -m venv venv
source venv/bin/activate

# Instalar dependencias
pip install -r requirements.txt

# Instalar proyecto
pip install -e .
```

## Uso

### Interfaz Web (Recomendado)

```bash
# Iniciar servidor web
python run_web.py

# Abrir en navegador
# http://localhost:5000
```

### Linea de Comandos (CLI)

```bash
# Verificar wallet Ethereum
python main.py crypto check 0x742d35Cc6634C0532925a3b844Bc9e7595f2bD3e

# Verificar wallet Bitcoin
python main.py crypto check 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa

# Analizar URL de phishing
python main.py phishing url https://suspicious-site.com

# Verificar email en brechas
python main.py breach user@email.com

# Analizar dominio
python main.py domain example.com

# Analizar proyecto crypto
python main.py project MiProyecto https://example.com --github https://github.com/user/repo
```

## Estructura del Proyecto

```
OsintPro/
├── main.py                    # CLI principal
├── run_web.py                 # Iniciar interfaz web
├── requirements.txt           # Dependencias
├── src/                       # Modulos principales
│   ├── crypto/               # Analisis blockchain
│   ├── phishing/             # Deteccion de phishing
│   ├── domain_analysis/      # Analisis de dominios/proyectos
│   ├── breach_monitor/       # Monitoreo de brechas
│   └── utils/                # Utilidades compartidas
├── web/                       # Interfaz web
│   ├── app.py                # Servidor Flask
│   ├── templates/            # HTML templates
│   └── static/               # CSS, JS, imagenes
├── tests/                    # Pruebas
├── reports/                  # Reportes generados
└── config/                   # Configuracion
```

## API Keys (Opcional)

Copia `config/settings.env` a `.env` y agrega tus API keys:

```bash
cp config/settings.env .env
```

Keys disponibles:
- `ETHERSCAN_API_KEY` - Para análisis Ethereum
- `VIRUSTOTAL_API_KEY` - Para verificación de URLs
- `HIBP_API_KEY` - Para verificación de brechas

## Aviso Ético

Este proyecto está diseñado **únicamente** para:
- Investigación y educación
- Análisis de proyectos legítimos
- Detección de amenazas para protección propia
- Verificación de seguridad personal

**NO** está diseñado para:
- Atacar sistemas sin autorización
- Recopilar datos privados sin consentimiento
- Realizar actividades ilegales

## Licencia

MIT License