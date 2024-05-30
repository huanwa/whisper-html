# audio_transcriber.py 文件内容

from gradio_client import Client

# 定义全局变量 API_URL 和 client 实例
API_URL = "https://sanchit-gandhi-whisper-jax.hf.space/"  # 使用正确的设备IP和端口号
client = Client(API_URL)

def transcribe_audio(audio_path, task="transcribe", return_timestamps=False):
    """
    使用 Gradio 端点转录音频文件的函数。
    
    :param audio_path: 音频文件的路径。
    :param task: 转录任务的名称。
    :param return_timestamps: 是否返回时间戳。
    :return: 转录的文本。
    """
    try:
        # 调用 Gradio 客户端进行预测
        text, runtime = client.predict(
            audio_path,
            task,
            return_timestamps,
            api_name="/predict_1",
        )
        return text
    except Exception as e:
        print(f"转录音频时发生错误：{e}")
        return None