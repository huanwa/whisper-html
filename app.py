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
#from audio_transcriber import transcribe_audio
import uuid

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
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], uploaded_file_name)

    user_info = session.get('user')
    if user_info:
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
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    audio_details = {
        'transcription_id': str(uuid.uuid4()),  # 生成唯一ID
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

def can_upload_file(user_email, new_upload_seconds=0):
    """
    检查用户在当前自然月内的上传时长是否超过了120分钟。
    """
    start_of_month, end_of_month = get_current_month_range()

    query = supabase.table("audio_files") \
                    .select("audio_length_seconds") \
                    .filter("user_email", "eq", user_email) \
                    .filter("upload_time", "gte", start_of_month.isoformat()) \
                    .filter("upload_time", "lt", end_of_month.isoformat())

    results = query.execute()
    
    total_seconds_this_month = sum(item['audio_length_seconds'] for item in results.data) if results.data else 0
    if total_seconds_this_month + new_upload_seconds > 7200:  # 120分钟换算成秒
        return {"can_upload": False, "message": "Uploaded duration exceeds the maximum limit for this month."}
    else:
        return {"can_upload": True, "message": "You can upload the file."}




@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    if file and allowed_file(file.filename):
        user_info = session.get('user')
        if not user_info:
            return jsonify({'error': 'User not logged in'}), 401
        
        userinfo = user_info.get('userinfo', {})
        user_email = userinfo.get('email')

        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        file_details = process_uploaded_file(filename)
        if 'error' in file_details:
            return jsonify(file_details), 400

        new_upload_seconds = file_details['audio_length_seconds']
        permission = can_upload_file(user_email, new_upload_seconds=new_upload_seconds)

        if permission.get('can_upload'):
            whisper_file = WhisperTranscriptionFile()
            try:
                transcribed_text = whisper_file.transcribe(file_path)
                if not transcribed_text:
                    return jsonify({'error': 'Failed to transcribe file'}), 500
                
                # 更新文件详细信息
                file_details['transcription_text'] = transcribed_text
                response = supabase.table("audio_files").insert(file_details).execute()

                if not response.data:
                    return jsonify({'error': 'Failed to save file info to database'}), 500

                return jsonify({
                    'message': 'File uploaded and transcription successful',
                    'transcribed_text': transcribed_text
                })
            except Exception as exc:
                return jsonify({'error': 'Failed to transcribe file', 'details': str(exc)}), 500
        else:
            return jsonify({"error": "Upload limit exceeded", "details": permission.get('message')}), 403

    return jsonify({'error': 'File not allowed'}), 400



@app.route("/history", methods=["GET"])
def get_user_history():
    user_info = session.get('user')
    if user_info:
        userinfo = user_info.get('userinfo', {})
        user_email = userinfo.get('email')
    else:
        return jsonify({'error': 'User email not found'}), 400

    query = supabase.table("audio_files").select("*").filter("user_email", "eq", user_email).filter("is_deleted", "eq", False).execute()
    if query.data:
        return jsonify(query.data)
    else:
        return jsonify([])




@app.route('/transcription/<transcription_id>', methods=['GET'])
def get_transcription(transcription_id):
    try:
        query = supabase.table('audio_files').select('*').filter('transcription_id', 'eq', transcription_id).execute()
        if query.data:
            return jsonify(query.data[0])
        else:
            return jsonify({'error': 'Transcription not found'}), 404
    except Exception as e:
        print(f"Error retrieving transcription: {e}")  # 打印错误信息
        return jsonify({'error': 'Internal Server Error'}), 500



@app.route('/transcription/<transcription_id>', methods=['DELETE'])
def delete_transcription(transcription_id):
    try:
        response = supabase.table('audio_files').update({'is_deleted': True}).eq('transcription_id', transcription_id).execute()
        if response.data:
            return jsonify({'message': 'Transcription marked as deleted successfully'}), 200
        else:
            return jsonify({'error': 'Failed to mark transcription as deleted'}), 500
    except Exception as e:
        print(f"Error marking transcription as deleted: {e}")  # 打印错误信息
        return jsonify({'error': 'Internal Server Error'}), 500



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
        return render_template("file_to_text copy 2.html", userinfo=userinfo)
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
    # 尝试获取session中的userinfo
    userinfo = session.get("user", {}).get("userinfo", None)
    
    # 如果userinfo存在，则认为用户已登录，渲染file_to_text copy.html
    if userinfo:
        return render_template("youtube_to_text.html", userinfo=userinfo)
    # 如果userinfo不存在，则认为用户未登录，渲染index.html
    else:
        return render_template("index.html")
    


@app.route('/usages')
def get_usages():
    userinfo = session.get("user", {}).get("userinfo", None)
    
    # 如果用户未登录，重定向到首页
    if not userinfo:
        return render_template("index.html")

    user_email = userinfo['email']
    start_of_month, end_of_month = get_current_month_range()

    query = supabase.table("audio_files") \
                    .select("audio_length_seconds") \
                    .filter("user_email", "eq", user_email) \
                    .filter("upload_time", "gte", start_of_month.isoformat()) \
                    .filter("upload_time", "lt", end_of_month.isoformat())
    
    results = query.execute()
    total_seconds_this_month = sum(item['audio_length_seconds'] for item in results.data) if results.data else 0
    total_minutes_this_month = total_seconds_this_month / 60

    return render_template("usages.html", userinfo=userinfo, minutes_used=total_minutes_this_month)










if __name__ == "__main__":
    app.run(host="0.0.0.0", port=env.get("PORT", 3000))
