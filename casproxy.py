from flask import Flask, redirect, request, jsonify
import requests
from xml.etree import ElementTree
import pypinyin
from pypinyin import lazy_pinyin
import time
import uuid
import jwt
import re
import time
import threading
from urllib.parse import urlencode, quote
import config  # Import configuration

app = Flask(__name__)

CAS_LOGIN_URL = config.CAS_LOGIN_URL
CAS_VALIDATE_URL = config.CAS_VALIDATE_URL
AUTHCAS_REDIRECT_URL = config.AUTHCAS_REDIRECT_URL
SERVICE_URL = config.SERVICE_URL
CLIENT_ID = config.CLIENT_ID
CLIENT_SECRET = config.CLIENT_SECRET
ACCESS_TOKEN_EXPIRY = config.ACCESS_TOKEN_EXPIRY
SECRET_KEY = config.SECRET_KEY
REDIRECT_URL_MATCH = config.REDIRECT_URL_MATCH
CLEANUP_INTERVAL = 600  # clean up every 10 minutes


tokens_store = {}
user_data_store = {}
redirect_uris = {}

def split_name(name: str):
    # 检查是否是纯英文名
    if re.fullmatch(r'[A-Za-z ]+', name):
        parts = name.split()
        # 将名和姓分别返回
        return parts[0], ' '.join(parts[1:]) if len(parts) > 1 else ''
    
    # 检查是否是中文名
    if len(name) <= 5 and re.fullmatch(r'[\u4e00-\u9fa5]+', name):
        # 将第一个字作为姓，剩下的作为名字
        lastname, firstname = name[0], name[1:]
        # 使用pypinyin将中文转换为拼音
        lastname_pinyin = ''.join(lazy_pinyin(lastname)).upper()
        firstname_pinyin = ''.join(lazy_pinyin(firstname)).capitalize()
        return firstname_pinyin, lastname_pinyin

    # 其他情况直接返回名字本身和一个空字符
    return name, ''

# def cleanup_tokens():
#     while True:
#         time.sleep(CLEANUP_INTERVAL)
#         current_time = time.time()
#         expired_tokens = [token for token, data in tokens_store.items() if data["exp"] <= current_time]
#         for token in expired_tokens:
#             tokens_store.pop(token, None)

# # Start the cleanup thread when the app starts
# cleanup_thread = threading.Thread(target=cleanup_tokens)
# cleanup_thread.start()

@app.route('/authorize')
def authorize():
    # Check client_id
    client_id = request.args.get('client_id')
    if client_id != CLIENT_ID:
        return jsonify(error="Invalid client_id"), 400
    
    # Capture the redirect_uri from Keycloak
    redirect_uri = request.args.get('redirect_uri')
    # print("redirect url is: ", redirect_uri)

    # validate redirect_uri
    if not redirect_uri.startswith(REDIRECT_URL_MATCH):
        return jsonify(error="Invalid redirect_uri"), 400

    # capture the state parameter from Keycloak
    state_keycloak = request.args.get('state')

    # 使用 session_id 作为 key 保存 redirect_uri
    session_id = "SESSION-"+str(uuid.uuid4())
    redirect_uris[session_id] = redirect_uri

    # capture the nonce parameter from Keycloak
    nonce = request.args.get('nonce')

    # Construct the service URL with the state parameter
    # service_url = f"{SERVICE_URL}?state={session_id}"
    service_url = f"{SERVICE_URL}"

    # URL encode the entire service URL
    encoded_service_url = quote(service_url, safe='')

    # Redirect to CAS for login with the URL encoded service parameter
    response = redirect(f"{CAS_LOGIN_URL}?service={encoded_service_url}")
    # put session_id in cookie
    response.set_cookie('session_id', session_id, httponly=True)
    response.set_cookie('state_keycloak', state_keycloak, httponly=True)
    response.set_cookie('nonce_keycloak', nonce, httponly=True)

    return response

@app.route('/callback')
def callback():


    # Retrieve the redirect_uri from cookie (session_id)
    session_id = request.cookies.get('session_id')
    # Retrieve the state parameter from cookie (state_keycloak)
    state_keycloak = request.cookies.get('state_keycloak')
    # Retrieve the nonce parameter from cookie (nonce_keycloak)
    nonce_keycloak = request.cookies.get('nonce_keycloak')

    ticket = request.args.get('ticket')
    if not ticket:
        return jsonify(error="No ticket provided"), 400

    params = {
        "service": SERVICE_URL,
        "ticket": ticket,
        "format": "XML"
    }
    response = requests.get(CAS_VALIDATE_URL, params=params)
    # Handle CAS response and extract user details
    # Add error handling for CAS response
    if response.status_code != 200:
        return jsonify(error="Failed to validate CAS ticket"), 400
    try:
        tree = ElementTree.fromstring(response.content)
        user = tree.find(".//{http://www.yale.edu/tp/cas}user").text
        attributes = tree.find(".//{http://www.yale.edu/tp/cas}attributes")
    except Exception as e:
        return jsonify(error=f"Error parsing CAS response: {str(e)}"), 500
    
    user = tree.find(".//{http://www.yale.edu/tp/cas}user").text
    attributes = tree.find(".//{http://www.yale.edu/tp/cas}attributes")
    sid = attributes.find("{http://www.yale.edu/tp/cas}sid").text
    email = attributes.find("{http://www.yale.edu/tp/cas}email").text
    # if email is empty and sid starts with 1, then it's a student, use sid@mail.sustech.edu.cn as email
    if not email and sid.startswith("1"):
        email = sid + "@mail.sustech.edu.cn"
    name = attributes.find("{http://www.yale.edu/tp/cas}name").text

    first_name, last_name = split_name(name)
    
    # Generate unique auth code
    auth_code = str(uuid.uuid4())

    user_data_store[auth_code] = {
        "sub": user,
        "sid": sid,
        "username": sid,
        "email": email,
        "given_name": first_name,
        "family_name": last_name,
        "nonce": nonce_keycloak,
    }
    redirect_uri = redirect_uris.pop(session_id, None)
    # print("redirect_uri at callback: "+str(redirect_uri))

    if not redirect_uri:
        return jsonify(error="Invalid state or session has expired"), 400

    # Redirect the user back to Keycloak with the auth code
    # print("auth code is: ", auth_code)
    return redirect(f"{redirect_uri}?code={auth_code}&state={state_keycloak}&nonce={nonce_keycloak}")

@app.route('/token', methods=['POST'])
def token():
    # Check client credentials
    client_id = request.form.get('client_id')
    client_secret = request.form.get('client_secret')
    
    if client_id != CLIENT_ID or client_secret != CLIENT_SECRET:
        return jsonify(error="Invalid client credentials"), 401

    # Check auth code
    auth_code = request.form.get('code')
    if auth_code not in user_data_store:
        return jsonify(error="Invalid auth code"), 400

    # Generate access token
    access_token_data = {
        "aud": CLIENT_ID,
        "sub": user_data_store[auth_code]["sub"],
        "nonce": user_data_store[auth_code]["nonce"],
        "exp": time.time() + ACCESS_TOKEN_EXPIRY
    }
    access_token = jwt.encode(access_token_data, SECRET_KEY, algorithm="HS256")
    
    tokens_store[access_token] = user_data_store[auth_code]
    
    del user_data_store[auth_code]  # delete auth code after use

    return jsonify(access_token=access_token, id_token=access_token, token_type="Bearer", scope="openid", expires_in=ACCESS_TOKEN_EXPIRY)

@app.route('/userinfo')
def userinfo():
    # Check access token
    access_token = request.headers.get('Authorization').split(" ")[1]  # Format: "Bearer <token>"
    # print(access_token)
    try:
        decoded_token = jwt.decode(access_token, SECRET_KEY, algorithms="HS256", audience=CLIENT_ID)
    except (jwt.ExpiredSignatureError, jwt.DecodeError):
        return jsonify(error="Invalid access token"), 401

    user_data = tokens_store.get(access_token)
    if not user_data:
        return jsonify(error="User data not found"), 404

    # print(user_data)
    return jsonify(user_data)

if __name__ == '__main__':
    app.run(host="11.9.20.4", port=59084, debug=False)
