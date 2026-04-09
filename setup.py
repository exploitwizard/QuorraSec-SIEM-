from setuptools import setup, find_packages
from pathlib import Path

long_description = ""
readme = Path(__file__).parent / "README.md"
if readme.exists():
    long_description = readme.read_text(encoding="utf-8")

setup(
    name="courra-sec",
    version="2.0.0",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        "app": ["templates/*.html", "static/**/*"],
        "sdk": ["*.js"],
    },
    install_requires=[
        # Core Flask stack
        "flask>=2.3.3",
        "flask-sqlalchemy>=3.0.5",
        "flask-cors>=4.0.0",
        "flask-sock>=0.2.0",
        "werkzeug>=2.3.7",

        # Cross-platform production WSGI server (works on Windows, Linux, macOS)
        "waitress>=2.1.2",

        # Rate limiting
        "flask-limiter>=3.5.0",

        # Security / TOTP 2FA
        "pyotp>=2.9.0",
        "RestrictedPython>=7.0",

        # Config / serialisation
        "python-dotenv>=1.0.0",
        "pyyaml>=6.0",

        # HTTP / WebSocket client
        "requests>=2.31.0",
        "websocket-client>=1.6.3",

        # GeoIP
        "geoip2>=4.7.0",

        # ML (optional but listed so pip installs them)
        "scikit-learn>=1.3.0",
        "pandas>=2.1.3",
        "numpy>=1.26.0",
        "matplotlib>=3.8.0",

        # Platform-aware data directories
        "platformdirs>=4.0.0",

        # Prometheus metrics
        "prometheus-client>=0.19.0",
    ],
    extras_require={
        "tls": ["trustme>=0.9.0"],
        "qr":  ["qrcode[pil]>=7.4.2"],
    },
    entry_points={
        "console_scripts": [
            "courra-sec=courra-sec:main",
        ],
    },
    author="Security Team",
    author_email="",
    description="Cross-platform SIEM tool for Block Fortress application",
    long_description=long_description,
    long_description_content_type="text/markdown",
    keywords="siem security monitoring block-fortress cross-platform",
    url="",
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: System :: Logging",
        "Topic :: System :: Monitoring",
        "Environment :: Web Environment",
        "Framework :: Flask",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
)
