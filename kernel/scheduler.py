"""Simple service scheduling primitive."""
import threading

class Scheduler:
    def __init__(self):
        self._timers = []

    def call_later(self, delay, callback):
        timer = threading.Timer(delay, callback)
        timer.daemon = True
        timer.start()
        self._timers.append(timer)
        return timer
