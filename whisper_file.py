# 假设为 whisper_file.py

import websocket
import json
import random
import string
import base64
import threading
import os

class WhisperTranscriptionFile:
    def __init__(self, ws_url="wss://sanchit-gandhi-whisper-jax.hf.space/queue/join"):
        self.ws_url = ws_url
        self.session_hash = self.generate_session_hash()
        self.FN_INDEX = 3
        self.output_data = ""
        self.transcribed_text = None

    def generate_session_hash(self):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=16))

    def on_message(self, ws, message):
        response = json.loads(message)
        
        if response['msg'] == 'send_data':
            threading.Thread(target=self.upload_audio, args=(ws,)).start()
        elif response['msg'] == 'process_completed':
            data = response.get('output', {}).get('data', [])
            if len(data) > 1:
                self.transcribed_text = data[0]
                print("Transcribed text:", self.transcribed_text)
            ws.close()

    def on_error(self, ws, error):
        print("Error:", error)

    def on_close(self, ws, close_status_code, close_msg):
        print("Closed WebSocket connection.")
        self.event.set()

    def on_open(self, ws):
        ws.send(json.dumps({"fn_index": self.FN_INDEX, "session_hash": self.session_hash}))

    def upload_audio(self, ws):
        filename = os.path.basename(self.audio_path)

        with open(self.audio_path, 'rb') as audio_file:
            base64_audio = base64.b64encode(audio_file.read()).decode('utf-8')

        data_to_send = {
            "data": [
                {
                    "data": f"data:audio/mpeg;base64,{base64_audio}",
                    "name": filename
                },
                "transcribe",
                True
            ],
            "event_data": None,
            "fn_index": self.FN_INDEX,
            "session_hash": self.session_hash,
        }

        ws.send(json.dumps(data_to_send))

    def transcribe(self, audio_path):
        self.audio_path = audio_path
        self.event = threading.Event()

        ws_app = websocket.WebSocketApp(self.ws_url,
                                        on_open=self.on_open,
                                        on_message=self.on_message,
                                        on_error=self.on_error,
                                        on_close=self.on_close)

        ws_thread = threading.Thread(target=ws_app.run_forever)
        ws_thread.start()

        self.event.wait()  # Wait for the transcription to complete
        return self.transcribed_text