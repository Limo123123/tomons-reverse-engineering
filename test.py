import sys
import time
from tomons_charger import TomonsCharger, InateckTag, ChargerTelemetry

# Windows stdout auf UTF-8 setzen
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# Live MQTT Zugangsdaten (vom Tomons / Licheng-Tech Broker)
BROKER    = "tomons-app.licheng-tech.com"
PORT      = 1883
USER      = "user_c6b65682c7544051b1ccd7ea7"
PASS      = "7932f254d3c375e9ff9e7d9b460e0116"
DEVICE_ID = "8dd6c767a1bb2bd074ec96dd9f24748a"

print("=" * 65)
print("  Tomons / Inateck Wallbox EV Charger - Live Telemetrie Client")
print("=" * 65)

charger = TomonsCharger(
    broker=BROKER,
    port=PORT,
    user=USER,
    password=PASS,
    device_id=DEVICE_ID
)

# Callback für fertig decodierte Live-Telemetrie
def on_telemetry(data: ChargerTelemetry):
    v_str = f"{data.voltage_v:>6.1f} V" if data.voltage_v is not None else "  (wartet auf Entschlüsselung)"
    i_str = f"{data.current_a:>6.2f} A" if data.current_a is not None else "  (wartet auf Entschlüsselung)"
    p_str = f"{data.power_w:>6d} W" if data.power_w is not None else "  (wartet auf Entschlüsselung)"
    t_str = f"{data.temperature_c:>6d} °C" if data.temperature_c is not None else "  (wartet auf Entschlüsselung)"
    lim_str = f"{data.max_current_a:>6d} A" if data.max_current_a is not None else "  (wartet auf Entschlüsselung)"
    print("\n+----------------------------------------------------------+")
    print("|            TOMONS / INATECK LIVE TELEMETRIE              |")
    print("+----------------------------------------------------------+")
    print(f"|  Spannung:          {v_str:<36} |")
    print(f"|  Strom:             {i_str:<36} |")
    print(f"|  Wirkleistung:      {p_str:<36} |")
    print(f"|  Temperatur:        {t_str:<36} |")
    print(f"|  Stromgrenze:       {lim_str:<36} |")
    print(f"|  Lademodus:         {data.charge_mode:<36} |")
    print(f"|  Kabelstatus:       {data.cable_status:<36} |")
    print(f"|  Online-Status:     {'Online' if data.is_online else 'Offline':<36} |")
    print("+----------------------------------------------------------+")

charger.on_telemetry_received = on_telemetry

# Optionale Callbacks für Detail-Debugging
def on_tag(tag: InateckTag):
    print(f"  [TAG] 0x{tag.tag_id:04X} ({tag.name}) -> Wert={tag.int_value}")

def on_raw(topic: str, payload: bytes):
    print(f"[MQTT] {topic} ({len(payload)} Bytes) -> {payload[:16].hex()}...")

charger.on_tag_received = on_tag
charger.on_raw_message = on_raw

print(f"\nVerbinde mit Broker '{BROKER}:{PORT}'...")
if charger.connect(timeout=5.0):
    print(f"[OK] Erfolgreich verbunden! Client-ID: {charger.client_id}")
    print(f"[OK] Subscribed: {charger.wildcard_topic}")

    # Statusabfrage (Tag 0xCE01) an die Wallbox senden
    print(f"\n[SENDE] Statusabfrage (Tag 0xCE01) an {charger.write_topic}...")
    charger.request_status()

    # Optional: Stromgrenze setzen, falls als Argument übergeben (z.B. python test.py --set 10)
    if len(sys.argv) >= 3 and sys.argv[1] == "--set":
        try:
            target_amps = int(sys.argv[2])
            print(f"[SENDE] Setze Stromgrenze auf {target_amps} A (Tag 0xC20A)...")
            charger.set_charging_current(target_amps)
        except ValueError:
            print("[WARNUNG] Ungültiger Stromwert.")

    # Auf eingehende Telemetrie lauschen
    print("[INFO] Lausche auf Live-Telemetriedaten (12 Sekunden)...\n")
    time.sleep(12)

    charger.disconnect()
    print("\n[FERTIG] Test erfolgreich beendet.")
else:
    print("[FEHLER] Verbindung zum MQTT Broker fehlgeschlagen.")
