import json
import threading
import asyncio
from queue import Queue, Empty
from mqtt_producer import MQTTProducer

SERVER_IP = "80.225.239.163" 
MQTT_USER = "my_mqtt_user"
MQTT_PASS = "mqttpassword"
TOPIC = "agent/events"

class EventDispatcher:
    def __init__(self, stdout: bool = False):
        self._queue = Queue(maxsize=50000)
        self._stdout = stdout
        self._stop = threading.Event()
        self._loop = None  

        self._mqtt = MQTTProducer(
            server_ip=SERVER_IP,
            mqtt_user=MQTT_USER,
            mqtt_pass=MQTT_PASS,
            mqtt_topic=TOPIC
        )

        self._thread = threading.Thread(
            target=self._thread_entry,
            daemon=True,
            name="sentinel-dispatcher"
        )
        self._thread.start()

    def _thread_entry(self):
        """Initializes a completely isolated, standalone event loop on this OS thread."""
        import sys
        
        # Fix for Windows asyncio loop selection inside a background thread
        if sys.platform == 'win32':
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
            
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        
        self._loop.run_until_complete(self._worker())
        self._loop.close()

    async def _worker(self):
        print("⚡ Sentinel Dispatcher Pipeline Engine Active.")
        while not self._stop.is_set():
            try:
                event = self._queue.get(timeout=0.5)
                
                await self._mqtt.push(event.get("event") , event.get("machine_info"))
                self._queue.task_done()

            except Empty:
                continue
            except Exception as e:
                print(f"⚠️ Dispatcher Network Transfer Error: {e}")
                await asyncio.sleep(2)

    def push(self, event_dict: dict , machine_info:dict|None):
        try:
            final_event = {"event" : event_dict , "machine_info" : machine_info}
            self._queue.put_nowait(final_event)
            if self._stdout:
                print(f"📦 Event queued successfully: {event_dict.get('type')}")
        except Exception:
            print("🚨 Event queue max capacity reached! Dropping oldest event packet.")

    def flush_and_stop(self):
        print("🛑 Shutting down Dispatcher... Processing remaining queue packets.")
        self._stop.set()
        self._thread.join(timeout=5)
