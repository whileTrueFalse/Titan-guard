# real_time_protection.py

import os
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from antivirus import Antivirus

class RealTimeProtectionHandler(FileSystemEventHandler):
    def __init__(self, antivirus):
        self.antivirus = antivirus

    def on_created(self, event):
        if not event.is_directory:
            result = self.antivirus.scan_file(event.src_path)
            print(result)

    def on_modified(self, event):
        if not event.is_directory:
            result = self.antivirus.scan_file(event.src_path)
            print(result)

class RealTimeProtection:
    def __init__(self, path='.'):
        self.path = path
        self.antivirus = Antivirus()
        self.observer = Observer()

    def start(self):
        event_handler = RealTimeProtectionHandler(self.antivirus)
        self.observer.schedule(event_handler, self.path, recursive=True)
        self.observer.start()
        print(f'Real-time protection started on {os.path.abspath(self.path)}')

    def stop(self):
        self.observer.stop()
        self.observer.join()
        print('Real-time protection stopped.')
