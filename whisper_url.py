# 在一个新文件（如whisper_url.py）中保存以下内容

import websocket
import json
import random
import string
import threading

class WhisperTranscription:
    def __init__(self, ws_url="wss://sanchit-gandhi-whisper-jax.hf.space/queue/join"):
        self.ws_url = ws_url
        self.session_hash = self.generate_session_hash()
        self.FN_INDEX = 6

    def generate_session_hash(self):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=16))

    def on_message(self, ws, message):
        response = json.loads(message)

        if response['msg'] == 'send_hash':
            ws.send(json.dumps({"fn_index": self.FN_INDEX, "session_hash": self.session_hash}))
        elif response['msg'] == 'send_data':
            # 这一步为空，因为我们将在一个单独的方法中发送数据
            pass
        elif response['msg'] == 'process_completed':
            data = response.get('output', {}).get('data', [])
            if len(data) > 1:
                transcribed_text = data[1]
                print("Transcribed text:")
                print(transcribed_text)
            ws.close()

    def on_error(self, ws, error):
        print("Error:", error)

    def on_close(self, ws, close_status_code, close_msg):
        print("Closed WebSocket connection.")

    def on_open(self, ws):
        print("WebSocket connection established.")
        def run(*args):
            ws.send(json.dumps({"fn_index": self.FN_INDEX, "session_hash": self.session_hash}))
        
        threading.Thread(target=run).start()

    def transcribe_video(self, video_url):
        def on_open(ws):
            self.on_open(ws)
            data_to_send = {
                "data": [video_url, "transcribe", False],
                "event_data": None,
                "fn_index": self.FN_INDEX,
                "session_hash": self.session_hash,
            }
            ws.send(json.dumps(data_to_send))
            
        ws_app = websocket.WebSocketApp(self.ws_url, on_open=on_open,
                                        on_message=self.on_message,
                                        on_error=self.on_error,
                                        on_close=self.on_close)

        ws_app.run_forever()