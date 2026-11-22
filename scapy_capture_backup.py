#!/usr/bin/env python3

import argparse
import gzip
from scapy.all import sniff, wrpcap, rdpcap, IP, TCP, Raw

INTERFACE = "eth0"
CAPTURE_FILTER = "tcp port 80"
OUTPUT_FILE = "captures/traffic.pcap"


def analyze_http(data, src, dst):
    """Разделяет HTTP-заголовки и тело, распаковывает gzip."""

    if b"\r\n\r\n" not in data:
        return

    headers, body = data.split(b"\r\n\r\n", 1)

    print("\n" + "=" * 65)
    print(f"Источник: {src}")
    print(f"Назначение: {dst}")
    print("-" * 65)

    print(headers.decode("utf-8", errors="replace"))

    if b"content-encoding: gzip" in headers.lower():
        try:
            body = gzip.decompress(body)
            print("\n[Тело ответа распаковано из gzip]")
        except (OSError, EOFError):
            print("\n[Тело gzip неполное: требуется сборка TCP-потока]")

    print("\n--- HTTP BODY ---")
    print(body[:3000].decode("utf-8", errors="replace"))
    print("=" * 65)


def analyze_packet(packet):
    if IP not in packet or TCP not in packet or Raw not in packet:
        return

    data = bytes(packet[Raw].load)

    markers = (b"GET ", b"POST ", b"HEAD ", b"HTTP/1.")

    if any(marker in data for marker in markers):
        analyze_http(
            data,
            f"{packet[IP].src}:{packet[TCP].sport}",
            f"{packet[IP].dst}:{packet[TCP].dport}"
        )


def capture():
    packets = []

    print("Интерфейс:", INTERFACE)
    print("Фильтр:", CAPTURE_FILTER)
    print("Захват HTTP-трафика начат.")
    print("Для остановки нажми Ctrl+C.")

    try:
        sniff(
            iface=INTERFACE,
            filter=CAPTURE_FILTER,
            prn=lambda packet: (
                packets.append(packet),
                analyze_packet(packet)
            ),
            store=False
        )
    except KeyboardInterrupt:
        print("\nЗахват остановлен.")

    if packets:
        wrpcap(OUTPUT_FILE, packets)
        print("Сохранено пакетов:", len(packets))
        print("Файл:", OUTPUT_FILE)
    else:
        print("Пакеты не обнаружены.")


def analyze_file(filename):
    packets = rdpcap(filename)

    print("Файл:", filename)
    print("Всего пакетов:", len(packets))

    for packet in packets:
        analyze_packet(packet)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Scapy HTTP traffic analyzer"
    )

    parser.add_argument(
        "--analyze",
        help="Путь к PCAP-файлу"
    )

    args = parser.parse_args()

    if args.analyze:
        analyze_file(args.analyze)
    else:
        capture()
