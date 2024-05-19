import requests
import json
from os import environ as env
from urllib.parse import quote_plus, urlencode
from authlib.integrations.flask_client import OAuth
from dotenv import find_dotenv, load_dotenv
from flask import Flask, redirect, render_template, session, url_for,jsonify,request
from werkzeug.utils import secure_filename
import os
from mutagen.mp3 import MP3
from datetime import datetime,timedelta
from dateutil.relativedelta import relativedelta
from supabase import create_client, Client
from whisper_url import WhisperTranscription
from whisper_file import WhisperTranscriptionFile

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)



app = Flask(__name__)
app.secret_key = env.get("APP_SECRET_KEY")
SUPABASE_URL = env.get("SUPABASE_URL")  # Supabase项目的URL
SUPABASE_KEY = env.get("SUPABASE_KEY")
# 初始化Supabase客户端
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

whisper_file = WhisperTranscriptionFile()


# 设置静态文件夹路径作为上传文件夹
UPLOAD_FOLDER = os.path.join(app.static_folder, 'uploads')
# 设置服务器可以接收的文件扩展名
ALLOWED_EXTENSIONS = {'mp3', 'wav', 'ogg'}

# 确保上传文件夹存在
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

#处理文件的基本信息
def process_uploaded_file(uploaded_file_name):
    # 构建完整的文件路径
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], uploaded_file_name)

     # 从session中获取用户邮箱
    user_info = session.get('user')  # 假设你将整个token存储在session的'user'键下
    if user_info:
    # 假设这里的token结构中有一个包含email的userinfo字段
        userinfo = user_info.get('userinfo', {})
        user_email = userinfo.get('email')
    else:
        user_email = None

    if not user_email:
        return {'error': 'User email not found'}

    if not os.path.isfile(file_path):
        return 'File not found.'

    file_size = os.path.getsize(file_path)

    audio = MP3(file_path)
    audio_length = audio.info.length

    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # 格式化时间

    audio_details = {
        'file_name': uploaded_file_name,
        'user_email': user_email,
        'file_size_bytes': file_size,
        'audio_length_seconds': audio_length,
        'upload_time': current_time
    }

    return audio_details
    

#上传文件之前，判断用户使用的时间
def get_current_month_range():
    """
    获取当前自然月的开始和结束日期。
    """
    now = datetime.now()
    start_of_month = datetime(now.year, now.month, 1)
    end_of_month = start_of_month + relativedelta(months=1) - timedelta(seconds=1)
    return start_of_month, end_of_month

def can_upload_file(user_email):
    """
    检查用户在当前自然月内的上传时长是否超过了120分钟。
    """
    # 获取当前月份的起始和结束时间
    start_of_month, end_of_month = get_current_month_range()
    
    # 构建查询
    query = supabase.table("audio_files") \
                    .select("audio_length_seconds") \
                    .filter("user_email", "eq", user_email) \
                    .filter("upload_time", "gte", start_of_month.isoformat()) \
                    .filter("upload_time", "lt", end_of_month.isoformat())
    
    # 执行查询并获取结果
    results = query.execute()
    
    # 检查是否查询成功，这里是修正后的代码
    try:
        results = query.execute()
        if not results or not results.data:
            print("发生了错误，请检查API调用和数据。")
        # 这里记录日志或通知用户
        else:
            total_length_this_month = sum(item['audio_length_seconds'] for item in results.data)
        # 处理上传逻辑

    except Exception as e:
        print(f"处理请求时发生异常：{e}")
    
    # 判断是否超过120分钟
    if total_length_this_month >= 7200:  # 120分钟换算成秒
        return {"can_upload": False, "message": "Uploaded duration exceeds the maximum limit for this month."}
    else:
        return {"can_upload": True, "message": "You can upload the file."}






#上传文件
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'})
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'})
    
    if file and allowed_file(file.filename):
        # 从session中获取用户邮箱
        user_info = session.get('user')  # 假设你将整个token存储在session的'user'键下
        if user_info:
            userinfo = user_info.get('userinfo', {})
            user_email = userinfo.get('email')
        else:
            return jsonify({'error': 'User email not found'})

        # 先判断本月使用时长
        permission = can_upload_file(user_email)
        if permission.get('can_upload'):
            # 上传文件
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            
            # 处理上传文件信息
            file_details = process_uploaded_file(filename)
            if 'error' not in file_details:
                # 插入文件信息到数据库
                response = supabase.table("audio_files").insert(file_details).execute()
                if not response.data:
                    return jsonify({'error': 'Failed to save file info to database'})
                try:
                    whisper_file = WhisperTranscriptionFile()
                    transcribed_text = whisper_file.transcribe(file_path)
                    print(transcribed_text)
                    # 假设 transcribe 方法会抛出异常
                except Exception as exc:
                    return jsonify({'error': 'Failed to transcribe file', 'details': str(exc)})
                return jsonify({
                    'message': 'File uploaded and transcription successful',
                    'transcribed_text': transcribed_text
                })
            else:
                return jsonify(file_details)
        else:
            # 如果超过使用时长
            return jsonify({"error": "Upload limit exceeded", "details": permission.get('message')})
    
    return jsonify({'error': 'File not allowed'})



oauth = OAuth(app)
supabase_headers = {
    'apikey': SUPABASE_KEY,
    'Authorization': 'Bearer ' + SUPABASE_KEY,
    'Content-Type': 'application/json'
}


oauth.register(
    "auth0",
    client_id=env.get("AUTH0_CLIENT_ID"),
    client_secret=env.get("AUTH0_CLIENT_SECRET"),
    client_kwargs={
        "scope": "openid profile email",
    },
    server_metadata_url=f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration',
)




@app.route("/login")
def login():
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True)
    )


# 回调路由，获取用户数据
@app.route("/callback", methods=["GET", "POST"])
def callback():
    token = oauth.auth0.authorize_access_token()
    session["user"] = token
    
    userinfo = token.get("userinfo")
    if userinfo:
        email = userinfo.get("email")
        
        if email:
            # 查询Supabase以检查用户是否已存在
            response = requests.get(
                f"{SUPABASE_URL}/rest/v1/userinfo?select=id&email=eq.{email}",
                headers=supabase_headers
            )
            user_exists = len(response.json()) > 0
            
            # 如果用户不存在，则添加到数据库
            if not user_exists:
                name = userinfo.get("name")
                locale = userinfo.get("locale")
                picture = userinfo.get("picture")
                
                payload = {
                    "name": name,
                    "email": email,
                    "locale": locale,
                    "picture": picture,
                }
                
                response = requests.post(
                    f"{SUPABASE_URL}/rest/v1/userinfo",
                    headers=supabase_headers,
                    json=payload
                )
                
                if response.status_code != 201:
                    print(f"Failed to insert data: {response.text}")
    
    return redirect("/")


#返回用户登录之后信息到页面
@app.route("/")
def home():
    # 尝试获取session中的userinfo
    userinfo = session.get("user", {}).get("userinfo", None)
    
    # 如果userinfo存在，则认为用户已登录，渲染file_to_text copy.html
    if userinfo:
        return render_template("file_to_text copy.html", userinfo=userinfo)
    # 如果userinfo不存在，则认为用户未登录，渲染index.html
    else:
        return render_template("index.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        "https://"
        + env.get("AUTH0_DOMAIN")
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("home", _external=True),
                "client_id": env.get("AUTH0_CLIENT_ID"),
            },
            quote_via=quote_plus,
        )
    )






# 对应 'File to Text' 页面的内容
@app.route('/getContentForFileToText')
def get_content_for_file_to_text():
    # 根据需要渲染的模板来进行处理
    return render_template('file_to_text.html')

# 对应 'YouTube to Text' 页面的内容
@app.route('/getContentForYouTubeToText')
def get_content_for_youtube_to_text():
    # 根据需要渲染的模板来进行处理
    return render_template('youtube_to_text.html')

# 对应 'Setting' 页面的内容
@app.route('/getContentForSetting')
def get_content_for_setting():
    # 根据需要渲染的模板来进行处理
    return render_template('setting.html')

# 对应 'Audio Cutter' 页面的内容
@app.route('/getContentForAudioCutter')
def get_content_for_audio_cutter():
    # 根据需要渲染的模板来进行处理
    return render_template('audio_cutter.html')

# 对应 'Audio Joiner' 页面的内容
@app.route('/getContentForAudioJoiner')
def get_content_for_audio_joiner():
    # 根据需要渲染的模板来进行处理
    return render_template('audio_joiner.html')








if __name__ == "__main__":
    app.run(host="0.0.0.0", port=env.get("PORT", 3000))
