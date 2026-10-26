"""
Tomons / Inateck EV Charger (Wallbox) Python Client
Reverse engineered from the Tomons Android App (com.tomons.charger)
Cloud Provider: Shenzhen Licheng Technology Co., Ltd. (licheng-tech.com)
"""

import struct
import json
import time
import logging
from dataclasses import dataclass, field
from typing import List, Tuple, Dict, Any, Optional, Callable

try:
    from Crypto.Cipher import AES
except ImportError:
    AES = None  # Requires 'pip install pycryptodome' for encryption support

try:
    import paho.mqtt.client as mqtt
except ImportError:
    mqtt = None  # Requires 'pip install paho-mqtt'

logger = logging.getLogger("tomons_charger")

# Default Known API Endpoints
API_BASE_URL = "https://tomons-app.licheng-tech.com/api/"
API_FALLBACK_URL = "http://wan2.licheng-tech.com:5010/api/"
DEFAULT_MQTT_BROKER = "tomons-app.licheng-tech.com"
DEFAULT_MQTT_PORT = 1883

# BLE UUIDs (for local Bluetooth communication)
BLE_SERVICE_UUID = "0000ffe0-0000-1000-8000-00805f9b34fb"
BLE_CHAR_UUID    = "0000ffe1-0000-1000-8000-00805f9b34fb"
BLE_CCCD_UUID    = "00002902-0000-1000-8000-00805f9b34fb"

# Dynamic Key Derivation Algorithm (reverse-engineered from libapp.so at 0x4905e8)
def derive_session_key_iv(base_key: bytes, base_iv: bytes, seed16: int) -> Tuple[bytes, bytes]:
    """
    Derives unique session AES-128 key and IV from base key, base IV, and packet 16-bit seed.
    Replicates exact ARM64 vector loop from libapp.so (0x4905e8).
    """
    w2 = (seed16 >> 8) & 0xFF
    w5 = seed16 & 0xFF

    # Loop 1: table1 (16 bytes)
    table1 = bytearray(16)
    for i in range(16):
        w6 = i & 1
        b = w2 if w6 == 0 else w5
        t = (b ^ (i * 0x5a)) & 0xFF
        rot = i & 3
        rotated = ((t << rot) | (t >> (8 - rot))) & 0xFF if rot else t
        other_b = w5 if w6 == 0 else w2
        table1[i] = (rotated ^ other_b) & 0xFF

    # Loop 2: out_key (16 bytes)
    out_k = bytearray(16)
    for i in range(16):
        x4 = base_key[i] ^ table1[i]
        rot = (table1[i] + i) & 7
        rotated = ((x4 << rot) | (x4 >> (8 - rot))) & 0xFF if rot else x4
        idx2 = (i + 7) & 0x0F
        out_k[i] = (rotated ^ table1[idx2]) & 0xFF

    # Loop 3: out_iv (16 bytes)
    out_iv = bytearray(16)
    for i in range(16):
        t_rev = table1[15 - i]
        x2 = base_iv[i] ^ t_rev
        rot = (t_rev + i) & 7
        rotated = ((x2 << rot) | (x2 >> (8 - rot))) & 0xFF if rot else x2
        idx3 = (i + 11) & 0x0F
        out_iv[i] = (rotated ^ table1[idx3]) & 0xFF

    return bytes(out_k), bytes(out_iv)


# Hardware Base Keys & IVs extracted from DeviceKeyManager runtime heap
HARDWARE_BASE_KEYS: Dict[int, Tuple[bytes, bytes]] = {
    0x10: (bytes.fromhex("9355afc5624eaf39d9695f3a1d5c41ca"), bytes.fromhex("45c1723a412108d5b10404b22e5182d7")),
    0x12: (bytes.fromhex("004bda72a64bec6810793ebe710f4e7f"), bytes.fromhex("34d459bf1cee85c8511d4931057b3be6")),
    0x14: (bytes.fromhex("bfaaead2082df4f18e8a65782202ddb5"), bytes.fromhex("57f48923e74b169d60ca05b83fad7210")),
    0x16: (bytes.fromhex("65a2c006e19f06f9d5afd89d6b97c186"), bytes.fromhex("8e48ee2d398e6e5bd22f0ae72fc94304")),
}

# Full Candidate Pool for fallback discovery
FALLBACK_BASE_KEYS: List[bytes] = [
    bytes.fromhex("648d23cae95861bb8df3f5a3074261f6"),
    bytes.fromhex("d79be3cf2d613cf8b8d690ae22aaa89c"),
    bytes.fromhex("50faa6dcb841a09499e7ba8788868a28"),
    bytes.fromhex("9355afc5624eaf39d9695f3a1d5c41ca"),
    bytes.fromhex("2dc5b88243db82d16d2594224d1068e2"),
    bytes.fromhex("004bda72a64bec6810793ebe710f4e7f"),
    bytes.fromhex("9a2df745881c67bd30e659af14d3824b"),
    bytes.fromhex("9ddedae26c19c30266d74b3b18510682"),
    bytes.fromhex("bfaaead2082df4f18e8a65782202ddb5"),
    bytes.fromhex("6ed5812f47b916fa9c53e07a34c8ae12"),
    bytes.fromhex("3c9768ae1d58fc74e6328bd049a715f2"),
    bytes.fromhex("57f48923e74b169d60ca05b83fad7210"),
    bytes.fromhex("db12d91f25f90cee3d74c83d7c8073a5"),
    bytes.fromhex("63a17979f9cbb2e85c248069c8c10f7a"),
    bytes.fromhex("65a2c006e19f06f9d5afd89d6b97c186"),
    bytes.fromhex("6a2d284037a402ac70d204c1c033ebba"),
    bytes.fromhex("45c1723a412108d5b10404b22e5182d7"),
    bytes.fromhex("7b5d14afcf2fbdf449a65993e6295793"),
    bytes.fromhex("34d459bf1cee85c8511d4931057b3be6"),
    bytes.fromhex("b31f294c710a8c52dd6180ddd5ab733a")
]

# Well-known Inateck Protocol Tag IDs
TAG_SET_CURRENT        = 0xC20A  # Set / report charging current limit in centi-Amperes (e.g. 600, 800, 1000, 1600, 3200)
TAG_START_STOP         = 0x0002  # Start (1) / Stop (0) charging
TAG_METRICS            = 0xC302  # Real-time electrical metrics (Voltage, Current, Power)
TAG_TEMPERATURE        = 0x002A  # PCB / ambient temperature in °C
TAG_STATUS_CONNECTION  = 0x0013  # Connection / Link state
TAG_WIFI_CONFIG        = 0x0014  # Wi-Fi SSID / Password / MQTT Config
TAG_SUB_SYNC           = 0x005D  # Device Tag Subscription Sync
TAG_RTC_TIME           = 0xC10D  # Local time sync (fake timestamp)
TAG_TIMEZONE           = 0xC20C  # Timezone configuration ID
TAG_PHASE_MISSING_WARN = 0xC222  # Warning toggle for missing phase
TAG_CABLE_STATE        = 0xC30A  # Cable / EV connection status (01 00 = unplugged)
TAG_CHARGE_MODE        = 0xC314  # Charge mode ID
TAG_NFC_CARD_LIST      = 0xC312  # RFID/NFC Cards registered
TAG_NFC_RECORD_MODE    = 0xC313  # NFC Card pairing mode
TAG_REQUEST_STATUS     = 0xCE01  # Request full status update from Wallbox
TAG_SHARE_REVOKED      = 0xCE03  # Share permission revoked

TAG_NAMES = {
    TAG_SET_CURRENT: "Charging Current Limit (A)",
    TAG_START_STOP: "Charging Switch (Start/Stop)",
    TAG_METRICS: "Electrical Metrics (V, A, W)",
    TAG_TEMPERATURE: "Temperature (°C)",
    TAG_STATUS_CONNECTION: "Connection Status",
    TAG_WIFI_CONFIG: "Wi-Fi Config",
    TAG_SUB_SYNC: "Subscription Sync",
    TAG_RTC_TIME: "RTC Local Timestamp",
    TAG_TIMEZONE: "Timezone Config",
    TAG_PHASE_MISSING_WARN: "Phase Missing Warning",
    TAG_CABLE_STATE: "Cable Connection State",
    TAG_CHARGE_MODE: "Charging Mode",
    TAG_NFC_CARD_LIST: "NFC Card List",
    TAG_NFC_RECORD_MODE: "NFC Pairing Mode",
    TAG_REQUEST_STATUS: "Status Request / Telemetry",
    TAG_SHARE_REVOKED: "Share Access Revoked",
}


def crc16_ccitt(data: bytes, init_val: int = 0xFFFF) -> int:
    """Computes CRC-16 (CCITT / XMODEM) with polynomial 0x1021."""
    crc = init_val
    for b in data:
        crc ^= (b << 8)
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


class InateckTag:
    """Represents a Tag-Length-Value (TLV) field in the Inateck Application Layer."""
    def __init__(self, tag_id: int, value: bytes = b""):
        self.tag_id = tag_id
        self.value = value

    @property
    def name(self) -> str:
        return TAG_NAMES.get(self.tag_id, f"Tag_0x{self.tag_id:04X}")

    @property
    def int_value(self) -> int:
        if not self.value:
            return 0
        return int.from_bytes(self.value, byteorder="big")

    def encode(self) -> bytes:
        if self.tag_id > 0xFF:
            tag_bytes = self.tag_id.to_bytes(2, byteorder="big")
        else:
            tag_bytes = self.tag_id.to_bytes(1, byteorder="big")

        length = len(self.value)
        if length < 0x80:
            len_bytes = bytes([length])
        elif length <= 0xFF:
            len_bytes = bytes([0x81, length])
        else:
            len_bytes = bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])

        return tag_bytes + len_bytes + self.value

    @classmethod
    def decode_stream(cls, data: bytes) -> List["InateckTag"]:
        tags = []
        idx = 0
        while idx < len(data):
            first_byte = data[idx]
            idx += 1
            if first_byte in (0x2A, 0xC1, 0xC2, 0xC3, 0xCE, 0xCF) and idx < len(data):
                if first_byte == 0x2A:
                    tag_id = 0x002A
                else:
                    tag_id = (first_byte << 8) | data[idx]
                    idx += 1
            else:
                tag_id = first_byte

            if idx >= len(data):
                break

            len_byte = data[idx]
            idx += 1
            if len_byte < 0x80:
                length = len_byte
            elif len_byte == 0x81 and idx < len(data):
                length = data[idx]
                idx += 1
            elif len_byte == 0x82 and idx + 1 < len(data):
                length = (data[idx] << 8) | data[idx + 1]
                idx += 2
            else:
                length = len_byte & 0x7F

            if idx + length > len(data):
                break

            val = data[idx : idx + length]
            idx += length
            tags.append(cls(tag_id, val))
        return tags

    def __repr__(self) -> str:
        return f"InateckTag(id=0x{self.tag_id:04X} [{self.name}], len={len(self.value)}, val={self.value.hex()}, int={self.int_value})"


class InateckPacket:
    """
    Inateck protocol packet framing:
    Header (9 Bytes):
      [0]     Sync Byte (0xA5)
      [1]     Length byte (total packet length minus 2)
      [2]     Control Byte (0x68 = send/report, 0x60 = receive)
      [3]     Sequence Number
      [4..6]  3-byte Session Token
      [6..8]  16-bit Seed for AES derivation: (raw[6] << 8) | raw[7]
      [8]     Key ID (0x10, 0x12, 0x14, 0x16...)
    Payload:
      [9:]    AES-128-CBC Ciphertext (multiple of 16 bytes: 16, 32, 64 bytes)
    """
    HEADER_BYTE = 0xA5

    def __init__(self,
                 packet_type: int = 0x01,
                 control_byte: int = 0x68,
                 key_id: int = 0x12,
                 session_id: int = 0x01,
                 payload: bytes = b"",
                 encrypted: bool = False,
                 raw_data: Optional[bytes] = None):
        self.packet_type = packet_type
        self.control_byte = control_byte
        self.key_id = key_id
        self.session_id = session_id
        self.payload = payload
        self.encrypted = encrypted
        self.raw_data = raw_data

    def build(self) -> bytes:
        """Encodes an outgoing packet to the Wallbox (e.g. for status query or control)."""
        payload_data = self.payload
        # Unencrypted command format (e.g. CE01 status request):
        if not self.encrypted:
            length = len(payload_data) + 7
            header = bytes([
                self.HEADER_BYTE,
                0x01, 0x00, 0x00,
                self.session_id,
                0x00, 0x01, 0x00,
                len(payload_data)
            ])
            pkt = header + payload_data
            crc = crc16_ccitt(pkt)
            return pkt + struct.pack(">H", crc)

        # Encrypted packet builder
        bk, biv = HARDWARE_BASE_KEYS.get(self.key_id, (FALLBACK_BASE_KEYS[5], FALLBACK_BASE_KEYS[18]))
        seed16 = (int(time.time()) & 0xFFFF)
        sk, siv = derive_session_key_iv(bk, biv, seed16)

        pad_len = 16 - (len(payload_data) % 16)
        padded = payload_data + bytes([pad_len] * pad_len)
        cipher = AES.new(sk, AES.MODE_CBC, siv)
        ciphertext = cipher.encrypt(padded)

        total_len = 9 + len(ciphertext)
        token_3b = bytes([(seed16 >> 8) & 0xFF, seed16 & 0xFF, (seed16 >> 8) & 0xFF])
        header = bytes([
            self.HEADER_BYTE,
            total_len - 2,
            self.control_byte,
            self.session_id,
            token_3b[0], token_3b[1], (seed16 >> 8) & 0xFF, seed16 & 0xFF,
            self.key_id
        ])
        return header + ciphertext

    @classmethod
    def parse(cls, data: bytes) -> "InateckPacket":
        """Parses and decrypts an incoming packet from the Wallbox."""
        if len(data) < 3:
            raise ValueError(f"Packet too short: {len(data)} bytes")

        if data[0] != cls.HEADER_BYTE:
            raise ValueError(f"Invalid packet header: expected 0xA5, got 0x{data[0]:02X}")

        # 1. Plain unencrypted status request format
        if len(data) == 15 and data[1] == 0x01:
            raw_payload = data[9:-2]
            return cls(
                packet_type=data[1],
                control_byte=data[2],
                session_id=data[4],
                payload=raw_payload,
                encrypted=False,
                raw_data=data
            )

        # 2. Encrypted Wallbox streaming packets (e.g. 73 bytes, 41 bytes, 25 bytes)
        if len(data) >= 9:
            ctrl = data[2]
            seq = data[3]
            seed16 = (data[6] << 8) | data[7]
            key_id = data[8]
            ciphertext = data[9:]

            # Attempt decryption with registered hardware base keys
            bk, biv = HARDWARE_BASE_KEYS.get(key_id, (None, None))
            decrypted_payload = b""

            if bk is not None and biv is not None and AES is not None:
                try:
                    sk, siv = derive_session_key_iv(bk, biv, seed16)
                    cipher = AES.new(sk, AES.MODE_CBC, siv)
                    pt = cipher.decrypt(ciphertext)
                    pad = pt[-1]
                    if 1 <= pad <= 16 and pt[-pad:] == bytes([pad] * pad):
                        decrypted_payload = pt[:-pad]
                except Exception as ex:
                    logger.debug(f"Direct decryption failed: {ex}")

            # Fallback search if direct key didn't decrypt
            if not decrypted_payload and AES is not None and len(ciphertext) >= 16:
                for cand_bk in FALLBACK_BASE_KEYS:
                    for cand_biv in FALLBACK_BASE_KEYS:
                        try:
                            sk, siv = derive_session_key_iv(cand_bk, cand_biv, seed16)
                            cipher = AES.new(sk, AES.MODE_CBC, siv)
                            pt = cipher.decrypt(ciphertext)
                            pad = pt[-1]
                            if 1 <= pad <= 16 and pt[-pad:] == bytes([pad] * pad):
                                decrypted_payload = pt[:-pad]
                                # Cache discovered key
                                HARDWARE_BASE_KEYS[key_id] = (cand_bk, cand_biv)
                                break
                        except Exception:
                            pass
                    if decrypted_payload:
                        break

            return cls(
                packet_type=data[1],
                control_byte=ctrl,
                key_id=key_id,
                session_id=seq,
                payload=decrypted_payload if decrypted_payload else ciphertext,
                encrypted=True,
                raw_data=data
            )

        return cls(packet_type=0x01, payload=data[2:], encrypted=False, raw_data=data)


@dataclass
class ChargerTelemetry:
    """Decoded live telemetry from Tomons / Inateck Wallbox."""
    voltage_v: Optional[float] = None          # Mains line voltage in V
    current_a: Optional[float] = None          # Active charging current in A
    power_w: Optional[int] = None              # Active power in Watts
    temperature_c: Optional[int] = None        # Charger/PCB temperature in °C
    max_current_a: Optional[int] = None        # Configured max current limit in A
    charge_mode: str = "Unbekannt"             # Charging mode (Sofortladen, etc.)
    cable_status: str = "Unbekannt"            # Cable status
    is_online: bool = True
    session_id: int = 0
    timestamp: float = field(default_factory=time.time)
    raw_tags: Dict[int, Any] = field(default_factory=dict)
    encrypted_payload: Optional[bytes] = None

    def __repr__(self) -> str:
        v_str = f"{self.voltage_v:.1f}V" if self.voltage_v is not None else "N/A"
        c_str = f"{self.current_a:.2f}A" if self.current_a is not None else "N/A"
        p_str = f"{self.power_w}W" if self.power_w is not None else "N/A"
        t_str = f"{self.temperature_c}°C" if self.temperature_c is not None else "N/A"
        lim_str = f"{self.max_current_a}A" if self.max_current_a is not None else "N/A"
        return (
            f"<ChargerTelemetry: {v_str}, {c_str}, {p_str}, {t_str} | "
            f"Limit: {lim_str} | Mode: {self.charge_mode} | Cable: {self.cable_status}>"
        )


class InateckFragmentManager:
    """
    Processes decrypted telemetry packets and streams from device/{device_id}/send.
    Extracts physical electrical metrics (Voltage, Current, Power, Temperature, Limit).
    Persists last known confirmed device state (e.g. current limit) across sessions.
    """
    def __init__(self, device_id: str = ""):
        self.device_id = device_id
        self.last_telemetry: ChargerTelemetry = ChargerTelemetry()
        self._cache_file = f".{device_id}_state.json" if device_id else None
        self._load_cached_state()

    def _load_cached_state(self):
        if not self._cache_file:
            return
        try:
            import os
            if os.path.exists(self._cache_file):
                with open(self._cache_file, "r") as f:
                    data = json.load(f)
                    if "max_current_a" in data and data["max_current_a"]:
                        self.last_telemetry.max_current_a = int(data["max_current_a"])
        except Exception:
            pass

    def _save_cached_state(self):
        if not self._cache_file:
            return
        try:
            with open(self._cache_file, "w") as f:
                json.dump({"max_current_a": self.last_telemetry.max_current_a}, f)
        except Exception:
            pass

    def process_packet(self, data: bytes) -> Optional[ChargerTelemetry]:
        """Processes raw incoming packet, decrypts if needed, and updates live telemetry."""
        if len(data) < 4 or data[0] != 0xA5:
            return None

        packet = InateckPacket.parse(data)
        if not packet.payload:
            return None

        payload = packet.payload
        updated = False

        # Ignore outgoing client commands (starting with 'Sy' / 0x53 0x79)
        if payload.startswith(b"\x53\x79"):
            return None

        # 1. Electrical Metrics Tag 0xC302 (Voltage, Current, Power)
        # Format: c3 02 0e [6 zero bytes] [Voltage 2B in 0.1V] [Current 2B in 0.01A] [Power 2B in W]
        m_idx = payload.find(b"\xc3\x02\x0e")
        if m_idx != -1 and m_idx + 15 < len(payload):
            try:
                v_raw = int.from_bytes(payload[m_idx + 9 : m_idx + 11], "big")
                if 1000 <= v_raw <= 5000:
                    self.last_telemetry.voltage_v = round(v_raw / 10.0, 1)
                    updated = True

                i_raw = int.from_bytes(payload[m_idx + 11 : m_idx + 13], "big")
                self.last_telemetry.current_a = round(i_raw / 100.0, 2)

                p_raw = int.from_bytes(payload[m_idx + 13 : m_idx + 15], "big")
                self.last_telemetry.power_w = p_raw
                updated = True
            except Exception as ex:
                logger.debug(f"Metrics unpack error: {ex}")
        elif len(payload) == 22:
            try:
                # Voltage at offset 14 (0x0e): Uint16 in tenths of a Volt (e.g. 3827 = 382.7 V)
                v_raw = int.from_bytes(payload[14:16], "big")
                if 1000 <= v_raw <= 5000:
                    self.last_telemetry.voltage_v = round(v_raw / 10.0, 1)
                    updated = True

                # Current at offset 16 (0x10): Uint16 in hundredths of an Ampere
                i_raw = int.from_bytes(payload[16:18], "big")
                self.last_telemetry.current_a = round(i_raw / 100.0, 2)

                # Power at offset 18 (0x12): Uint16 in Watts
                p_raw = int.from_bytes(payload[18:20], "big")
                self.last_telemetry.power_w = p_raw
                updated = True
            except Exception as ex:
                logger.debug(f"Metrics unpack error: {ex}")

        # 2. Current Limit: Tag 0xC20A in centi-Amperes (e.g. 0x0258 = 600 -> 6A, 0x0320 = 800 -> 8A)
        c20a_idx = payload.find(b"\xc2\x0a")
        if c20a_idx != -1 and c20a_idx + 3 < len(payload):
            val_raw = int.from_bytes(payload[c20a_idx + 2 : c20a_idx + 4], "big")
            if 600 <= val_raw <= 3200:
                self.last_telemetry.max_current_a = round(val_raw / 100.0)
                self._save_cached_state()
                updated = True

        # 3. Status and State Tags (Temperature, Cable state, Charging mode)
        # Temperature: Tag 0x2A (1 Byte in °C)
        t_idx = payload.find(b"\x2a")
        if t_idx != -1 and t_idx + 1 < len(payload):
            temp = payload[t_idx + 1]
            if 0 <= temp <= 90:
                self.last_telemetry.temperature_c = temp
                updated = True

        # Cable state: Tag 0xC30A (01 00 = unplugged / standby)
        c_idx = payload.find(b"\xc3\x0a")
        if c_idx != -1 and c_idx + 3 < len(payload):
            val = payload[c_idx + 2 : c_idx + 4]
            if val == b"\x01\x00":
                self.last_telemetry.cable_status = "Nicht verbunden (Standby)"
            elif val == b"\x01\x01":
                self.last_telemetry.cable_status = "Verbunden (Warten)"
            elif val == b"\x01\x02":
                self.last_telemetry.cable_status = "Lädt aktiv"
            updated = True

        # Charging mode: Tag 0xC314
        m_idx = payload.find(b"\xc3\x14")
        if m_idx != -1 and m_idx + 2 < len(payload):
            m_val = payload[m_idx + 2]
            mode_map = {0x00: "Sofortladen (Immediate)", 0x01: "Geplant (Scheduled)", 0x02: "PV-Überschuss"}
            self.last_telemetry.charge_mode = mode_map.get(m_val, f"Modus_{m_val}")
            updated = True

        # 2. Tag Stream Block (from decrypted 73-byte packet or general tags)
        try:
            tags = InateckTag.decode_stream(payload)
            for t in tags:
                self.last_telemetry.raw_tags[t.tag_id] = t.int_value

                # Temperature: Tag 0x002A (1 Byte in °C)
                if t.tag_id == TAG_TEMPERATURE:
                    self.last_telemetry.temperature_c = t.int_value
                    updated = True

                # Current limit: Tag 0x0001 (1 Byte in A)
                elif t.tag_id == TAG_SET_CURRENT:
                    self.last_telemetry.max_current_a = t.int_value
                    updated = True

                # Cable status: Tag 0xC30A (01 00 = unplugged / standby)
                elif t.tag_id == TAG_CABLE_STATE:
                    if t.value == b"\x01\x00":
                        self.last_telemetry.cable_status = "Nicht verbunden"
                    elif t.value == b"\x01\x01":
                        self.last_telemetry.cable_status = "Verbunden (Warten)"
                    elif t.value == b"\x01\x02":
                        self.last_telemetry.cable_status = "Lädt"
                    updated = True

                # Charging mode: Tag 0xC314
                elif t.tag_id == TAG_CHARGE_MODE:
                    mode_map = {0x00: "Sofortladen (Immediate)", 0x01: "Geplant (Scheduled)", 0x02: "PV-Überschuss"}
                    self.last_telemetry.charge_mode = mode_map.get(t.int_value, f"Modus_{t.int_value}")
                    updated = True

                # Link state
                elif t.tag_id == TAG_STATUS_CONNECTION:
                    self.last_telemetry.is_online = (t.int_value != 0)
                    updated = True
        except Exception as ex:
            logger.debug(f"Tag decode note: {ex}")

        if updated:
            self.last_telemetry.session_id = packet.session_id
            self.last_telemetry.timestamp = time.time()
            self.last_telemetry.is_online = True
            return self.last_telemetry

        return None


class TomonsCharger:
    """
    Direct MQTT Client for Tomons / Inateck Wallboxes / EV Chargers.
    Communicates directly with the cloud broker without requiring REST login.
    """
    def __init__(self,
                 broker: str = DEFAULT_MQTT_BROKER,
                 port: int = DEFAULT_MQTT_PORT,
                 user: str = "",
                 password: str = "",
                 device_id: str = "",
                 client_id: Optional[str] = None):
        if mqtt is None:
            raise ImportError("MQTT support requires 'paho-mqtt'. Please run: pip install paho-mqtt")

        self.broker = broker
        self.port = port
        self.user = user
        self.password = password
        self.device_id = device_id
        self.client_id = client_id or f"app_{device_id[:8]}"

        self.write_topic = f"device/{self.device_id}/send"
        self.read_topic = f"device/{self.device_id}/receive"
        self.wildcard_topic = f"device/{self.device_id}/#"

        # MQTT Client setup (support Paho MQTT v1 and v2)
        try:
            self._client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=self.client_id)
        except AttributeError:
            self._client = mqtt.Client(client_id=self.client_id)

        if self.user:
            self._client.username_pw_set(self.user, self.password)

        self._client.on_connect = self._on_connect
        self._client.on_message = self._on_message
        self._client.on_disconnect = self._on_disconnect

        self.is_connected = False
        self._session_counter = 1
        self.fragment_manager = InateckFragmentManager(device_id=self.device_id)

        # User callbacks
        self.on_telemetry_received: Optional[Callable[[ChargerTelemetry], None]] = None
        self.on_tag_received: Optional[Callable[[InateckTag], None]] = None
        self.on_packet_received: Optional[Callable[[InateckPacket], None]] = None
        self.on_raw_message: Optional[Callable[[str, bytes], None]] = None

    def _on_connect(self, client, userdata, flags, rc, properties=None):
        rc_code = getattr(rc, "value", rc)
        if rc_code == 0:
            self.is_connected = True
            logger.info(f"Connected to {self.broker}:{self.port} as {self.client_id}")
            client.subscribe(self.wildcard_topic)
            logger.info(f"Subscribed to {self.wildcard_topic}")
        else:
            logger.error(f"MQTT Connection failed with code {rc}")

    def _on_disconnect(self, client, userdata, flags, rc, properties=None):
        self.is_connected = False
        logger.warning(f"Disconnected from MQTT broker (rc={rc})")

    def _on_message(self, client, userdata, msg):
        logger.debug(f"Received msg on {msg.topic}: {len(msg.payload)} bytes")

        if self.on_raw_message:
            self.on_raw_message(msg.topic, msg.payload)

        # 1. Process telemetry streaming and decryption
        try:
            telemetry = self.fragment_manager.process_packet(msg.payload)
            if telemetry and self.on_telemetry_received:
                self.on_telemetry_received(telemetry)
        except Exception as ex:
            logger.debug(f"Telemetry processing note: {ex}")

        # 2. Parse tags for individual callbacks
        try:
            packet = InateckPacket.parse(msg.payload)
            if self.on_packet_received:
                self.on_packet_received(packet)

            if packet.payload:
                tags = InateckTag.decode_stream(packet.payload)
                for tag in tags:
                    if self.on_tag_received:
                        self.on_tag_received(tag)
        except Exception as ex:
            logger.debug(f"Packet parse note: {ex}")

    def connect(self, timeout: float = 5.0) -> bool:
        """Connects to the MQTT broker and starts background loop."""
        self._client.connect(self.broker, self.port, keepalive=60)
        self._client.loop_start()
        start = time.time()
        while not self.is_connected and (time.time() - start < timeout):
            time.sleep(0.1)
        return self.is_connected

    def disconnect(self):
        """Disconnects and stops the network thread."""
        self._client.loop_stop()
        self._client.disconnect()
        self.is_connected = False

    def publish_packet(self, packet: InateckPacket, topic: Optional[str] = None):
        """Publishes an InateckPacket to the wallbox."""
        data = packet.build()
        target_topic = topic or self.write_topic
        logger.debug(f"Publishing {len(data)} bytes to {target_topic}: {data.hex()}")
        self._client.publish(target_topic, data)

    def request_status(self):
        """Sends CE01 status query to request current wallbox telemetry."""
        self._session_counter = (self._session_counter + 1) & 0xFF
        pkt_bytes = build_status_request_packet(session_id=self._session_counter)
        self._client.publish(self.write_topic, pkt_bytes)

    def set_charging_current(self, current_amps: int):
        """Sets max charging current (e.g. 6, 8, 10, 13, 16, 20, 24, 32 A)."""
        self._session_counter = (self._session_counter + 1) & 0xFF
        pkt_bytes = build_set_charge_current_packet(current_amps, session_id=self._session_counter)
        self._client.publish(self.write_topic, pkt_bytes)
        # Update local telemetry and persist cached state
        self.fragment_manager.last_telemetry.max_current_a = current_amps
        self.fragment_manager._save_cached_state()

    def start_charging(self):
        """Sends command to start charging."""
        self._session_counter = (self._session_counter + 1) & 0xFF
        pkt_bytes = build_start_charging_packet(session_id=self._session_counter)
        self._client.publish(self.write_topic, pkt_bytes)

    def stop_charging(self):
        """Sends command to stop charging."""
        self._session_counter = (self._session_counter + 1) & 0xFF
        pkt_bytes = build_stop_charging_packet(session_id=self._session_counter)
        self._client.publish(self.write_topic, pkt_bytes)

    @classmethod
    def from_cloud(cls, email: str, password: str, device_id: Optional[str] = None) -> "TomonsCharger":
        """
        Creates and configures a TomonsCharger instance directly from Email & Password.
        Automatically logs into the Licheng Cloud API, discovers registered devices,
        retrieves MQTT broker credentials, and configures the client.
        Ideal for Home Assistant Config Flow and automation scripts.
        """
        cloud = TomonsCloudClient()
        cloud.login(email, password)
        devices = cloud.get_devices()
        if not devices:
            raise ValueError(f"No EV Chargers found in account {email}")

        selected = None
        if device_id:
            for d in devices:
                if d.get("auth_id") == device_id or d.get("device_identifier") == device_id or d.get("id") == device_id:
                    selected = d
                    break
        if not selected:
            selected = devices[0]

        target_auth_id = selected.get("auth_id") or selected.get("device_identifier")
        broker, port, user, pwd = cloud.get_mqtt_config()

        charger = cls(
            broker=broker,
            port=port,
            user=user,
            password=pwd,
            device_id=target_auth_id
        )
        charger.cloud_client = cloud
        return charger


# Command Builders
def build_status_request_packet(session_id: int = 0x01) -> bytes:
    """Builds a packet to request current Wallbox status (CE01)."""
    tags = InateckTag(TAG_REQUEST_STATUS, b"\x01").encode()
    pkt = InateckPacket(packet_type=0x01, session_id=session_id, payload=tags, encrypted=False)
    return pkt.build()


def build_set_charge_current_packet(current_amps: int, session_id: int = 0x71) -> bytes:
    """
    Builds the authentic encrypted packet to set max charging current (e.g. 6, 8, 10, 13, 16, 32 A).
    Encodes Tag 0xC20A with value = current_amps * 100 in centi-Amperes (e.g. 600, 800, 1000, 1600, 3200).
    Payload format: 53 79 [seq 2B] 5e 00 c2 0a [val 2B]
    """
    val = current_amps * 100
    seq = (int(time.time()) & 0xFFFF)
    payload = bytes([0x53, 0x79, (seq >> 8) & 0xFF, seq & 0xFF, 0x5E, 0x00, 0xC2, 0x0A, (val >> 8) & 0xFF, val & 0xFF])

    key_id = 0x10
    bk, biv = HARDWARE_BASE_KEYS[key_id]
    seed16 = (int(time.time() * 1000) & 0xFFFF)
    sk, siv = derive_session_key_iv(bk, biv, seed16)

    pad_len = 16 - (len(payload) % 16)
    padded = payload + bytes([pad_len] * pad_len)
    cipher = AES.new(sk, AES.MODE_CBC, siv)
    ciphertext = cipher.encrypt(padded)

    total_len = 9 + len(ciphertext)
    header = bytes([
        0xA5,
        total_len - 2,
        0x68,
        session_id & 0xFF,
        0x8D, 0x4B, (seed16 >> 8) & 0xFF, seed16 & 0xFF,
        key_id
    ])
    return header + ciphertext


def build_start_charging_packet(session_id: int = 0x01) -> bytes:
    """Builds an encrypted packet to start charging (Tag 0x0002 = 1)."""
    tags = InateckTag(TAG_START_STOP, b"\x01").encode()
    pkt = InateckPacket(packet_type=0x01, session_id=session_id, payload=tags, encrypted=True)
    return pkt.build()


def build_stop_charging_packet(session_id: int = 0x01) -> bytes:
    """Builds an encrypted packet to stop charging (Tag 0x0002 = 0)."""
    tags = InateckTag(TAG_START_STOP, b"\x00").encode()
    pkt = InateckPacket(packet_type=0x01, session_id=session_id, payload=tags, encrypted=True)
    return pkt.build()


# Licheng / Tomons Cloud REST API Client
class TomonsCloudClient:
    """
    Client for Tomons / Licheng HTTP REST API (Shenzhen Licheng Technology Co., Ltd.).
    Provides automatic authentication, session token refresh, device discovery,
    and MQTT credential retrieval for Home Assistant and Python integrations.
    """
    def __init__(self, base_url: str = API_BASE_URL):
        self.base_url = base_url.rstrip("/") + "/"
        self.email: Optional[str] = None
        self.password: Optional[str] = None
        self.token: Optional[str] = None
        self.user_info: Dict[str, Any] = {}
        self.devices: List[Dict[str, Any]] = []

    def login(self, email: str, password: str) -> Dict[str, Any]:
        """
        Authenticates with cloud REST API using email and password.
        Stores JWT bearer token and userInfo containing MQTT broker credentials.
        """
        import requests
        self.email = email
        self.password = password
        url = self.base_url + "auth/login"
        resp = requests.post(url, json={
            "account": email,
            "password": password,
            "login_type": "EMAIL"
        }, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        if data.get("code") != 200:
            msg = data.get("message", "Unknown error")
            raise ValueError(f"Login failed: {msg}")
        payload = data.get("data", {})
        self.token = payload.get("token")
        self.user_info = payload.get("userInfo", {})
        logger.info(f"Cloud login successful for {email}")
        return payload

    def _headers(self) -> Dict[str, str]:
        if not self.token:
            return {}
        return {"Authorization": f"Bearer {self.token}"}

    def _request_with_retry(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Executes a request, automatically re-authenticating if token expired (401)."""
        import requests
        if not self.token and self.email and self.password:
            self.login(self.email, self.password)

        url = self.base_url + endpoint.lstrip("/")
        headers = kwargs.pop("headers", {})
        headers.update(self._headers())

        resp = requests.request(method, url, headers=headers, **kwargs)
        if resp.status_code == 401 and self.email and self.password:
            logger.info("Session token expired, refreshing via re-login...")
            self.login(self.email, self.password)
            headers.update(self._headers())
            resp = requests.request(method, url, headers=headers, **kwargs)

        resp.raise_for_status()
        return resp.json()

    def get_devices(self) -> List[Dict[str, Any]]:
        """Fetches all registered Wallbox EV Chargers for this account."""
        data = self._request_with_retry("GET", "device/list")
        raw_list = data.get("data", [])
        self.devices = []
        for item in raw_list:
            dev = item.get("device") if isinstance(item.get("device"), dict) else item
            self.devices.append(dev)
        return self.devices

    def get_device_status(self, auth_id: str) -> Dict[str, Any]:
        """Fetches online status and heartbeat for a specific device."""
        data = self._request_with_retry("GET", "device/status", params={"auth_id": auth_id})
        return data.get("data", {})

    def get_mqtt_config(self) -> Tuple[str, int, str, str]:
        """Returns (broker, port, username, password) for MQTT connection."""
        broker = self.user_info.get("mqttBroker") or DEFAULT_MQTT_BROKER
        port = int(self.user_info.get("mqttPort") or DEFAULT_MQTT_PORT)
        user = self.user_info.get("mqttUsername") or ""
        pwd = self.user_info.get("mqttPassword") or ""
        return broker, port, user, pwd
