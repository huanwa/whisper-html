"""Python Flask WebApp Auth0 integration example
"""

import requests
import json
from os import environ as env
from urllib.parse import quote_plus, urlencode

from authlib.integrations.flask_client import OAuth
from dotenv import find_dotenv, load_dotenv
from flask import Flask, redirect, render_template, session, url_for

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

app = Flask(__name__)
app.secret_key = env.get("APP_SECRET_KEY")
SUPABASE_URL = env.get("SUPABASE_URL")  # Supabase项目的URL
SUPABASE_KEY = env.get("SUPABASE_KEY")


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


# Controllers API
# @app.route("/")
# def home():
#     return render_template(
#         "index.html",
#         session=session.get("user"),
#         pretty=json.dumps(session.get("user"), indent=4),
#     )




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
    userinfo = session.get("user", {}).get("userinfo", None)
    return render_template("index.html", userinfo=userinfo)


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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=env.get("PORT", 3000))
