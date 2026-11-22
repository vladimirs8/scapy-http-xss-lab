
import argparse
from urllib.parse import parse_qs

from scapy.all import sniff, wrpcap
from scapy.sessions import TCPSession
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.packet import Raw


INTERFACE = "eth0"
CAPTURE_FILTER = "tcp port 80"
OUTPUT_FILE = "captures/traffic.pcap"


def analyze_http(packet):
    if HTTPRequest in packet:
        request = packet[HTTPRequest]

        print("\n" + "=" * 65)
        print("ТИП: HTTP REQUEST")
        print("Источник:", packet[0][1].src)
        print("Назначение:", packet[0][1].dst)

        method = bytes(request.Method).decode("utf-8", errors="replace")
        host = bytes(request.Host).decode("utf-8", errors="replace")
        path = bytes(request.Path).decode("utf-8", errors="replace")

        print("Метод:", method)
        print("Host:", host)
        print("Путь:", path)

        if b"?" in request.Path:
            query = bytes(request.Path).split(b"?", 1)[1]
            params = parse_qs(query.decode("utf-8", errors="replace"))
            print("GET-параметры:", params)

        if Raw in packet:
            print("Тело запроса:")
            print(bytes(packet[Raw].load).decode("utf-8", errors="replace")[:2000])

        print("=" * 65)

    elif HTTPResponse in packet:
        response = packet[HTTPResponse]

        print("\n" + "=" * 65)
        print("ТИП: HTTP RESPONSE")
        print("Источник:", packet[0][1].src)
        print("Назначение:", packet[0][1].dst)

        status = bytes(response.Status_Code).decode("utf-8", errors="replace")
        print("Статус:", status)

        if hasattr(response, "Content_Type"):
            print("Content-Type:", response.Content_Type)

        if hasattr(response, "Content_Encoding"):
            print("Content-Encoding:", response.Content_Encoding)

        body = bytes(packet[Raw].load) if Raw in packet else b""

        print("\nСодержимое сообщения:")
        print(body[:3000].decode("utf-8", errors="replace"))

        markers = [
            (b"<blocked>", "Сервер заблокировал HTML-тег"),
            (b"<script>alert(", "Обнаружен JavaScript в HTML-ответе"),
            (b"onerror=", "Обнаружен обработчик onerror"),
            (b"onload=", "Обнаружен обработчик onload")
        ]

        for marker, description in markers:
            if marker.lower() in body.lower():
                print("[!] " + description)

        print("=" * 65)


def analyze_file(filename):
    print("Анализ файла:", filename)

    packets = sniff(
        offline=filename,
        session=TCPSession
    )

    print("Обработано пакетов:", len(packets))

    for packet in packets:
        analyze_http(packet)


def capture():
    print("Интерфейс:", INTERFACE)
    print("Фильтр:", CAPTURE_FILTER)
    print("Для остановки нажми Ctrl+C")

    try:
        packets = sniff(
            iface=INTERFACE,
            filter=CAPTURE_FILTER,
            store=True
        )

        wrpcap(OUTPUT_FILE, packets)

        print("\nСохранено пакетов:", len(packets))
        print("Файл:", OUTPUT_FILE)

    except KeyboardInterrupt:
        print("\nЗахват остановлен.")

    except Exception as error:
        print("Ошибка:", error)


def main():
    parser = argparse.ArgumentParser(
        description="Scapy HTTP Traffic Analyzer"
    )

    parser.add_argument(
        "--analyze",
        metavar="PCAP",
        help="Анализ существующего PCAP-файла"
    )

    args = parser.parse_args()

    if args.analyze:
        analyze_file(args.analyze)
    else:
        capture()


if __name__ == "__main__":
    main()
