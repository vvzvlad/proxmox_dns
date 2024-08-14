from zeroconf import ServiceBrowser, Zeroconf
import threading
import time

class MyListener:
    def remove_service(self, zeroconf, type, name):
        print(f"Сервис {name} удален")

    def add_service(self, zeroconf, type, name):
        info = zeroconf.get_service_info(type, name)
        print(f"Обнаружен сервис {name} на {info.server}:{info.port}, адреса {info.parsed_addresses()}")

def monitor_mdns():
    zeroconf = Zeroconf()
    listener = MyListener()
    browser = ServiceBrowser(zeroconf, "_http._tcp.local.", listener)
    try:
        while True:
            time.sleep(0.1)
    finally:
        zeroconf.close()

if __name__ == "__main__":
    thread = threading.Thread(target=monitor_mdns, daemon=True)
    thread.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Завершение работы...")
