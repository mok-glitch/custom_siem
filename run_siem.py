import threading
import time

from Collector.collector import start_collection
from Detection.detection import run_detection
from Dashboard.app import app


def collector_thread():
    start_collection()


def detection_thread():
    while True:
        run_detection()
        time.sleep(10)


def dashboard_thread():
    app.run(debug=True, use_reloader=False)


if __name__ == "__main__":
    print("🚀 Starting Custom SIEM...\n")

    t1 = threading.Thread(target=collector_thread)
    t2 = threading.Thread(target=detection_thread)
    t3 = threading.Thread(target=dashboard_thread)

    t1.start()
    t2.start()
    t3.start()

    t1.join()
    t2.join()
    t3.join()
