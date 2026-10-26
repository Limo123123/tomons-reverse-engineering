# Tomons / Inateck EV Wallbox Python Client & Reverse Engineering

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Device: EV Wallbox](https://img.shields.io/badge/Hardware-AC%20EV%20Wallbox%20Charger-brightgreen.svg)]()

Dieses Repository enthält die vollständige Dokumentation und eine native Python-Implementierung (`tomons_charger.py`) zur Steuerung und Telemetrie-Auswertung von **Tomons / Inateck Wallboxen (AC Electric Vehicle Chargers)** über das Cloud-MQTT- und REST-Protokoll.

> [!IMPORTANT]
> **Hardware-Fokus:** Die Marke Inateck stellt diverse IoT-Geräte her (Barcode-Scanner, Tastaturen, USB-Hubs). **Dieses Repository und die Python-Bibliothek sind speziell und exklusiv für die AC EV Wallboxen (Elektroauto-Ladestationen 11 kW / 22 kW)** der Marke Tomons / Inateck entwickelt worden.

Das Protokoll wurde durch Reverse-Engineering der offiziellen Android-App (`com.tomons.charger`, Version 1.1.5), statische Disassemblierung der nativen Flutter/ARM64-Engine (`libapp.so`) und Live-Traffic-Analyse via ADB/MQTT vollständig entschlüsselt.

---

## 📋 Inhaltsverzeichnis
1. [Hintergrund & Architektur](#-hintergrund--architektur)
2. [Zugangsdaten & Authentifizierung](#-zugangsdaten--authentifizierung)
3. [Telemetrie & Streaming-Verhalten](#-telemetrie--streaming-verhalten)
4. [Protokoll- & Paket-Framing](#-protokoll---paket-framing)
5. [Kryptografie: Dynamische AES-128-CBC Session-Schlüssel](#-kryptografie-dynamische-aes-128-cbc-session-schlüssel)
6. [Payload-Struktur der Telemetriedaten & Tag-Katalog](#-payload-struktur-der-telemetriedaten--tag-katalog)
7. [Python Library Referenz (`tomons_charger.py`)](#-python-library-referenz-tomons_chargerpy)
8. [Schnellstart & CLI-Client (`test.py`)](#-schnellstart--cli-client-testpy)
9. [Lade-Statistik & Die 1-kWh-Erfassungsregel](#-lade-statistik--die-1-kwh-erfassungsregel)
10. [Datenschutz & Git-Sicherheit](#-datenschutz--git-sicherheit)

---

## 🏛 Hintergrund & Architektur

Die Marke **Tomons** gehört zum Hardware-Hersteller **Inateck**. Als Cloud- und IoT-Dienstleister fungiert die Muttergesellschaft **Shenzhen Licheng Technology Co., Ltd.** (`licheng-tech.com`).

* **MQTT-Broker:** `tomons-app.licheng-tech.com` (Port `1883`)
* **Fallback-Broker:** `mqtt.licheng-tech.com` (Port `1883`, IP `80.251.210.33`)
* **Cloud REST API:** `https://tomons-app.licheng-tech.com/api/`

---

## 🔑 Zugangsdaten & Authentifizierung

### 1. Cloud REST-Login (Einfacher Weg)
Die API bietet einen Standard-Login-Endpunkt:
* **URL:** `POST https://tomons-app.licheng-tech.com/api/auth/login`
* **Payload:**
  ```json
  {
    "account": "user@example.com",
    "password": "secret_password",
    "login_type": "EMAIL"
  }
  ```
* **Antwort:** Liefert das JWT-Bearer-Token sowie das `userInfo`-Objekt mit den dynamisch zugewiesenen MQTT-Credentials (`mqttBroker`, `mqttPort`, `mqttUsername`, `mqttPassword`).

### 2. Lokaler App-Speicher (`OriginStorage.gs`)
Die Tomons-App basiert auf Flutter und verwendet **GetStorage** (GetX-Framework) anstelle der standardmäßigen Android SharedPreferences. Sämtliche Konfigurations-, Authentifizierungs- und Gerätedaten liegen in:
```text
/data/data/com.tomons.charger/app_flutter/OriginStorage.gs
```

Auf einem gerooteten Android-Gerät oder Emulator (z. B. BlueStacks) kann die Konfigurationsdatei direkt ausgelesen werden:
```cmd
adb shell "su -c 'cat /data/data/com.tomons.charger/app_flutter/OriginStorage.gs'"
```

---

## 📊 Telemetrie & Streaming-Verhalten

Die Wallbox überträgt kontinuierlich folgende Messwerte:
- **Netzspannung:** z. B. `230 V` (einphasig) bzw. `375 V` (dreiphasig)
- **Ladestrom:** z. B. `0.00 A` bis `32.00 A`
- **Wirkleistung:** z. B. `0 W` bis `11000 W`
- **Gehäusetemperatur:** z. B. `16 °C`
- **Eingestellte Stromgrenze:** z. B. `6 A`, `8 A`, `10 A`, `16 A`, `32 A`
- **Lademodus:** Sofortladen (Immediate), Geplant (Scheduled), PV-Überschuss
- **Kabelstatus:** Nicht verbunden (Standby), Verbunden (Warten), Lädt aktiv

### Bedarfsgesteuertes Streaming (Request / Response)
1. **Ruhezustand:** Wenn keine App aktiv ist, sendet die Wallbox keine kontinuierliche Telemetrie, sondern verbleibt im Low-Power-Heartbeat-Modus.
2. **Streaming anfordern:** Sendet man ein Status-Abfrage-Paket mit **Tag `0xCE01`** an das Topic `device/{device_id}/send`, startet die Wallbox das aktive Streaming und antwortet kontinuierlich alle 1 bis 2 Sekunden mit abwechselnd 41-Byte- und 73-Byte-Telemetriepaketen.

---

## 📡 Protokoll- & Paket-Framing

Alle Pakete beginnen mit dem Synchronisationsbyte `0xA5`.

### 1. Verschlüsselte Telemetrie- und Steuerpakete (`InateckPacket`)

```text
+------+---------+------+------+----------+------------+--------+--------------------------+
| 0xA5 | Len - 2 | Ctrl | Seq  | Token(3B)| Seed16(2B) | Key ID | AES-128 Ciphertext (N*16)|
| 1 B  | 1 B     | 1 B  | 1 B  | 3 B      | 2 B        | 1 B    | N * 16 Bytes             |
+------+---------+------+------+----------+------------+--------+--------------------------+
```

- **Byte 0 (`0xA5`):** Header-Sync-Byte.
- **Byte 1:** Gesamtlänge des Pakets minus 2.
- **Byte 2 (`0x68` / `0x60`):** Richtung/Control-Flags (`0x68` = Wallbox $\rightarrow$ App oder App $\rightarrow$ Wallbox).
- **Byte 3:** Sequenzzähler.
- **Byte 4..6:** 3-Byte Session-Token.
- **Byte 6..7:** 16-Bit Seed (`(raw[6] << 8) | raw[7]`) für die dynamische Schlüsselableitung.
- **Byte 8:** Hardware Key-ID (`0x10`, `0x12`, `0x14`, `0x16` ...).
- **Ab Byte 9:** AES-128-CBC Ciphertext mit PKCS7-Padding. *(Hinweis: Verschlüsselte Pakete enthalten keinen CRC-16 Trailer!)*

### 2. Unverschlüsselte Statusabfrage (`0xCE01`)

```text
+------+------+------+------+------+------+------+------+------+------+------+------+------+----------+
| 0xA5 | 0x01 | 0x00 | 0x00 | Sess | 0x00 | 0x01 | 0x00 | DLen | CE   | 01   | 01   | 01   | CRC-16   |
+------+------+------+------+------+------+------+------+------+------+------+------+------+----------+
```

---

## 🔐 Kryptografie: Dynamische AES-128-CBC Session-Schlüssel

Die Wallbox nutzt keine statischen AES-Schlüssel für die Paketverschlüsselung. Für jedes einzelne Paket wird aus dem im Paketheader übertragenen 16-Bit-Seed und dem gerätespezifischen Hardware-Basisschlüssel (`HARDWARE_BASE_KEYS`) ein dynamischer Session-Key und Session-IV berechnet.

Der Algorithmus wurde direkt aus der ARM64-Implementierung in `libapp.so` (Offset `0x4905e8`) abgeleitet:

```python
def derive_session_key_iv(base_key: bytes, base_iv: bytes, seed16: int) -> Tuple[bytes, bytes]:
    w2 = (seed16 >> 8) & 0xFF
    w5 = seed16 & 0xFF

    # Runde 1: 16-Byte Transformationstabelle ableiten
    table1 = bytearray(16)
    for i in range(16):
        w6 = i & 1
        b = w2 if w6 == 0 else w5
        t = (b ^ (i * 0x5a)) & 0xFF
        rot = i & 3
        rotated = ((t << rot) | (t >> (8 - rot))) & 0xFF if rot else t
        other_b = w5 if w6 == 0 else w2
        table1[i] = (rotated ^ other_b) & 0xFF

    # Runde 2: Session AES Key ableiten
    out_k = bytearray(16)
    for i in range(16):
        x4 = base_key[i] ^ table1[i]
        rot = (table1[i] + i) & 7
        rotated = ((x4 << rot) | (x4 >> (8 - rot))) & 0xFF if rot else x4
        idx2 = (i + 7) & 0x0F
        out_k[i] = (rotated ^ table1[idx2]) & 0xFF

    # Runde 3: Session AES IV ableiten
    out_iv = bytearray(16)
    for i in range(16):
        t_rev = table1[15 - i]
        x2 = base_iv[i] ^ t_rev
        rot = (t_rev + i) & 7
        rotated = ((x2 << rot) | (x2 >> (8 - rot))) & 0xFF if rot else x2
        idx3 = (i + 11) & 0x0F
        out_iv[i] = (rotated ^ table1[idx3]) & 0xFF

    return bytes(out_k), bytes(out_iv)
```

Die Hardware-Basisschlüssel für verschiedene Key-IDs sind in `all_device_base_keys.json` und im `tomons_charger.py` Modul hinterlegt:
* Key ID `0x10`: Key `9355afc5624eaf39d9695f3a1d5c41ca`, IV `45c1723a412108d5b10404b22e5182d7`
* Key ID `0x12`: Key `004bda72a64bec6810793ebe710f4e7f`, IV `34d459bf1cee85c8511d4931057b3be6`
* Key ID `0x14`: Key `bfaaead2082df4f18e8a65782202ddb5`, IV `57f48923e74b169d60ca05b83fad7210`
* Key ID `0x16`: Key `65a2c006e19f06f9d5afd89d6b97c186`, IV `8e48ee2d398e6e5bd22f0ae72fc94304`

---

## 📦 Payload-Struktur der Telemetriedaten & Tag-Katalog

Sobald der Ciphertext via AES-128-CBC entschlüsselt und das PKCS7-Padding entfernt wurde, liegt der Klartext-Payload vor:

### 1. 22-Byte Telemetrie-Metrik-Block (aus 41-Byte MQTT-Paket)
Enthält die schnellen elektrischen Echtzeitmesswerte:
* **Byte 14..15 (Uint16 Big-Endian):** Netzspannung in Zehntel Volt (`raw / 10.0`). Z. B. `3758` $\rightarrow$ **`375.8 V`**.
* **Byte 16..17 (Uint16 Big-Endian):** Ladestrom in Hundertstel Ampere (`raw / 100.0`). Z. B. `0` $\rightarrow$ **`0.00 A`**.
* **Byte 18..19 (Uint16 Big-Endian):** Wirkleistung in Watt. Z. B. `0` $\rightarrow$ **`0 W`**.

### 2. Tag-Katalog (aus 73-Byte MQTT-Paket & Befehlen)

| Tag ID | Name | Datentyp | Beschreibung |
| :--- | :--- | :--- | :--- |
| **`0xC20A`** | `TAG_SET_CURRENT` | `Uint16` (centi-A) | Eingestellte Stromgrenze ($A \times 100$). Z.B. `600` = 6 A, `800` = 8 A, `1000` = 10 A, `1600` = 16 A, `3200` = 32 A. |
| **`0x002A`** | `TAG_TEMPERATURE` | `Uint8` (°C) | Gehäusetemperatur der Wallbox. |
| **`0xC30A`** | `TAG_CABLE_STATUS` | `Bytes[2]` | `01 00`: Standby / Nicht verbunden<br>`01 01`: Verbunden / Warten<br>`01 02`: Lädt aktiv |
| **`0xC314`** | `TAG_MODE` | `Uint8` | `0`: Sofortladen (Immediate)<br>`1`: Zeitplan (Scheduled)<br>`2`: PV-Überschuss |
| **`0xCE01`** | `TAG_STATUS_REQUEST` | `Uint8` | Telemetrie-Aufweckbefehl (aktiviert Streaming). |
| **`0xC210`** | `TAG_TOTAL_ENERGY` | `Bytes[5]` | Kumulierte Gesamtladeenergie. |
| **`0xC101`** | `TAG_RFID_CONFIG` | `Bytes[N]` | Autorisierungskarten & RFID-Verwaltung. |

---

## 🐍 Python Library Referenz (`tomons_charger.py`)

Die Datei `tomons_charger.py` ist eine vollständig eigenständige Python-Bibliothek ohne externe Abhängigkeiten außer `paho-mqtt`, `pycryptodome` und `requests`.

### 1. `TomonsCloudClient`
Verwaltet den REST-API-Zugang, automatische Token-Erneuerung (Token-Refresh bei 401) und die Geräteauflistung:

```python
from tomons_charger import TomonsCloudClient

cloud = TomonsCloudClient(email="user@example.com", password="secret_password")

# Login durchführen und MQTT-Zugangsdaten erhalten:
user_info = cloud.login()
print("Broker:", user_info["mqttBroker"])
print("MQTT-User:", user_info["mqttUsername"])

# Registrierte Geräte auflisten:
devices = cloud.get_devices()
for dev in devices:
    print(f"Gerät: {dev['product_model_code']} | Auth-ID: {dev['auth_id']} | MAC: {dev['mac_address']}")
```

### 2. `TomonsCharger`
Verwaltet die MQTT-Verbindung zur Wallbox, decodiert Telemetrie und sendet verschlüsselte Befehle:

```python
from tomons_charger import TomonsCharger, ChargerTelemetry

# Automatische Erstellung via Cloud-Login:
charger = TomonsCharger.from_cloud(
    email="user@example.com",
    password="secret_password"
)

# Callback für eingehende Telemetrie registrieren:
def handle_telemetry(data: ChargerTelemetry):
    print(f"Spannung: {data.voltage_v} V | Strom: {data.current_a} A | Leistung: {data.power_w} W | Limit: {data.max_current_a} A")

charger.on_telemetry_received = handle_telemetry

# Verbinden & Aufwecken:
charger.connect()
charger.request_status()

# Ladestrom setzen (unterstützte Werte: 6, 8, 10, 13, 16, 20, 24, 32 A):
charger.set_charging_current(8)

# Ladevorgang starten / pausieren:
# charger.start_charging()
# charger.stop_charging()
```

### 3. Datenklasse `ChargerTelemetry`
```python
@dataclass
class ChargerTelemetry:
    voltage_v: Optional[float] = None       # z. B. 377.4 V
    current_a: Optional[float] = None       # z. B. 0.00 A
    power_w: Optional[int] = None           # z. B. 0 W
    temp_c: Optional[int] = None            # z. B. 16 °C
    max_current_a: Optional[int] = None     # z. B. 8 A
    mode: Optional[str] = None              # "Sofortladen (Immediate)", etc.
    cable_status: Optional[str] = None      # "Nicht verbunden (Standby)", etc.
    total_energy_kwh: Optional[float] = None# Kumulierte kWh
    is_online: bool = True
    timestamp: float = ...
```

---

## ⚡ Schnellstart & CLI-Client (`test.py`)

### 1. Installation
```bash
pip install paho-mqtt pycryptodome requests
```

### 2. Ausführung
* **Nur Telemetrie anzeigen (ohne Einstellungen zu verändern):**
  ```bash
  python test.py
  ```
* **Ladestromgrenze live verstellen (z. B. auf 8 A oder 10 A):**
  ```bash
  python test.py --set 8
  python test.py --set 10
  ```

---

## 📈 Lade-Statistik & Die 1-kWh-Erfassungsregel

In der Tomons-App existiert ein Reiter **Statistik** mit Diagrammen für Tag, Monat und Jahr (`PowerStatisticsPageState`).

### Warum ist die Statistik in der App anfangs leer (0.00 kWh)?
Beim Reverse-Engineering der Logik (`power_statistics/logic.dart` und `libapp.so`) wurde die offizielle Firmware- und Anwendungsregel ermittelt:
> **"Weniger als 1 kWh wird nicht statistisch erfasst"** *(engl. "Less than 1kWh will not be statisticed")*

* Die Wallbox erfasst und speichert Statistik-Einträge erst, wenn während eines Ladevorgangs **mindestens 1,0 kWh** elektrische Energie übertragen wurden.
* Ladevorgänge unter 1,0 kWh werden verworfen.
* **Tipp:** In unserer Home Assistant Integration (`ha-tomons-charger`) haben wir diesen Nachteil behoben, indem Home Assistant die Wirkleistung in Echtzeit integriert und somit auch kleinste Teilladungen lückenlos aufzeichnet!

---

## 🔒 Datenschutz & Git-Sicherheit

* **[`secrets.md`](secrets.md):** Enthält persönliche Zugangsdaten, Token-Dumps und MAC-Adressen für den privaten Eigenbedarf.
* **[`.gitignore`](.gitignore):** Schließt `secrets.md`, Cache-Dateien (`*.state.json`), APK-Dateien (`*.xapk`) und dekompilierte Ordner (`extracted_*`, `scratch_research/`) automatisch von Git-Commits aus.
* Es werden **keine Passwörter, Tokens oder urheberrechtlich geschützte APK-Dateien** auf GitHub hochgeladen.

---

## 📄 Lizenz
MIT License © 2026.
Dieses Projekt steht in keiner offiziellen Verbindung zu Shenzhen Licheng Technology Co., Ltd. oder Inateck / Tomons.
