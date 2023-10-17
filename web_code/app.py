import requests
from flask import Flask, render_template, request, redirect, session, url_for,flash
from mysql import Mysql
import pymysql
from datetime import timedelta
from authlib.integrations.flask_client import OAuth
from functools import wraps
import os
import random
import string
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import pymysql
from passlib.hash import pbkdf2_sha256
import config

app = Flask(__name__)
app.secret_key = "eungok"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=5)
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_TYPE'] = 'filesystem'

mysql = Mysql(password=config.password)

# OAuth Setup
oauth = OAuth(app)

# Naver OAuth
naver_client_id = config.naver_client_id
naver_client_secret = config.naver_client_secret
naver=oauth.register(
    name='naver',
    client_id = naver_client_id,
    client_secret = naver_client_secret,
    access_token_url = 'https://nid.naver.com/oauth2.0/token',
    access_token_params = None,
    authorize_url = 'https://nid.naver.com/oauth2.0/authorize',
    authorize_params = None,
    refresh_token_url = None,
    redirect_uri = 'http://eunahpae.pythonanywhere.com/callback',
    client_kwargs = {'scope': 'name email'})

# Google OAuth
google_client_id = config.google_client_id
google_client_secret = config.google_client_secret
google=oauth.register(
    name="google",
    client_id = google_client_id,
    client_secret = google_client_secret,
    access_token_url = "https://www.googleapis.com/oauth2/v4/token",
    access_token_params = None,
    authorize_url = "https://accounts.google.com/o/oauth2/v2/auth",
    authorize_params = None,
    api_base_url = "https://www.googleapis.com/oauth2/v3/",
    client_kwargs = {"scope": "openid email profile"},
    server_metadata_url = 'https://accounts.google.com/.well-known/openid-configuration')

# Kakao OAuth
kakao_client_id = config.kakao_client_id
kakao_client_secret = config.kakao_client_secret
kakao = oauth.register(
    name = 'kakao',
    client_id = kakao_client_id,
    client_secret = kakao_client_secret,
    access_token_url = 'https://kauth.kakao.com/oauth/token',
    access_token_params = None,
    authorize_url = 'https://kauth.kakao.com/oauth/authorize',
    authorize_params = None,
    refresh_token_url = None,
    redirect_uri = 'http://eunahpae.pythonanywhere.com/kakao-callback')

def is_loged_in(func):
    @wraps(func)
    def wrap(*args, **kwargs):
        if 'is_loged_in' in session:
            return func(*args, **kwargs)
        else:
            return redirect('/login')
    return wrap

def connect():
        return pymysql.connect(host=mysql.host, user=mysql.user, db=mysql.db, password=mysql.password, charset=mysql.charset)

# Generate a random verification code
def generate_verification_code():
    number = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    return number

# Send email verification link
def send_verification_email(email, number):
    db = connect()
    cursor = db.cursor()
    sql='SELECT * FROM user WHERE email = %s'
    cursor.execute(sql, [email])
    users = cursor.fetchone()
    print(users)
    if users==None:
        sql = '''
            INSERT INTO user (email, code )
            VALUES (%s ,%s )
        '''
        verification_code = pbkdf2_sha256.hash(number)
        print(number)
        cursor.execute(sql,(email, verification_code))
        db.commit()
        from_email = 'eunahp86@gmail.com'
        password = 'trwcpqrofghewkxy'
        subject = 'Email Verification'

        msg = MIMEMultipart()
        msg['From'] = from_email
        msg['To'] = email
        msg['Subject'] = subject

        verification_link = f'https://eunahpae.pythonanywhere.com/verify?email={email}&code={number}'
        message = f"Hello,\n\nPlease click the following link to verify your email:\n\n{verification_link}\n\nBest regards,\nYour Website Team"

        msg.attach(MIMEText(message, 'plain'))

        try:
            server = smtplib.SMTP('smtp.gmail.com', 587)
            server.starttls()
            server.login(from_email, password)
            server.sendmail(from_email, email, msg.as_string())
            server.quit()
            print('Email sent successfully!')
        except Exception as e:
            print(f'Error sending email: {e}')
    else:
        # print('ssssssss')
        sql = '''
            UPDATE user SET code = %s WHERE email = %s
        '''
        verification_code = pbkdf2_sha256.hash(number)
        # print(f"fewfwe: {verification_code}")
        cursor.execute(sql,( verification_code, email))
        db.commit()
        from_email = 'eunahp86@gmail.com'
        password = 'trwcpqrofghewkxy'
        subject = 'Email Verification'

        msg = MIMEMultipart()
        msg['From'] = from_email
        msg['To'] = email
        msg['Subject'] = subject

        verification_link = f'https://eunahpae.pythonanywhere.com/verify?email={email}&code={number}'
        message = f"Hello,\n\nPlease click the following link to verify your email:\n\n{verification_link}\n\nBest regards,\nYour Website Team"

        msg.attach(MIMEText(message, 'plain'))

        try:
            server = smtplib.SMTP('smtp.gmail.com', 587)
            server.starttls()
            server.login(from_email, password)
            server.sendmail(from_email, email, msg.as_string())
            server.quit()
            print('Email sent successfully!')
        except Exception as e:
            print(f'Error sending email: {e}')
        return 'Sent'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/email', methods=['GET', 'POST'])
def email():
    if request.method == 'POST':
        email = request.form.get('email')
        db = connect()
        curs = db.cursor()

        sql = f'SELECT * FROM user WHERE email = %s;'
        curs.execute(sql , email)
        rows = curs.fetchone()
        if rows:
            if rows[6] == '1':
                return render_template('login.html')
            else:
                # number = generate_verification_code()
                # send_verification_email(email, number)
                return render_template('register.html',email=email)
        else:
            # number = generate_verification_code()
            # send_verification_email(email, number)
            return render_template('register.html',email=email)
    else:
        return render_template('email.html')

@app.route('/auth')
def auth():
    email=request.args.get('email')
    return render_template('auth.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        phone = request.form.get('phone')
        password = request.form.get('password')
        number = generate_verification_code()
        send_verification_email(email, number)
        password = pbkdf2_sha256.hash(password)
        print(password)
        db = connect()
        curs = db.cursor()
        sql = f'UPDATE user SET username =%s, phone=%s,password=%s WHERE email = %s;'
        curs.execute(sql , (username,phone,password,email))
        print('ddddd')
        db.commit()
        db.close()

        # result = mysql.insert_user(username, email, phone, password)

        return render_template('auth.html', email=email)

    elif request.method == "GET":
        return redirect('/email')

# Verification route
@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if request.method == 'GET':
        email = request.args.get('email')
        code = request.args.get('code')
        db=connect()
        cursor = db.cursor()
        sql='SELECT * FROM user WHERE email = %s'
        cursor.execute(sql, [email])
        users = cursor.fetchone()
        print(users)
        if users == None:
            flash('Email not registered.')
            return "fail"
        else:
            if pbkdf2_sha256.verify(code, users[5]):
                flash('Email verified successfully.')
                sql = '''
                UPDATE user SET auth = %s WHERE email = %s
            '''
                cursor.execute(sql,( "1", email))
                db.commit()

                return redirect('/login')
            else:
                flash('Invalid verification code.')
                return "fail"

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "GET":
        return render_template('login.html')
    elif request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')
        db = connect()
        curs = db.cursor()

        sql = f'SELECT * FROM user WHERE email = %s;'
        curs.execute(sql , email)

        rows = curs.fetchall()
        print(rows)

        if rows:
            print(f'g,pwemrgpmptwmrom:{pbkdf2_sha256.verify(password, rows[0][4])}')
            result = pbkdf2_sha256.verify(password, rows[0][4])
            print(result)
            if result:
                session['is_loged_in'] = True
                session['username'] = rows[0][1]
                print(session['is_loged_in'])
                return redirect('/')
            else:
                return redirect('/login')
        else:
            return render_template('login.html')

# 네이버 로그인
@app.route('/naver')
def NaverLogin():
    return naver.authorize_redirect(redirect_uri=url_for('callback', _external=True))

@app.route('/callback')
def callback():
    naver_token = naver.authorize_access_token()
    user_info = naver.get('https://openapi.naver.com/v1/nid/me').json()
    # Process user_info and store session or user data as needed
    social_name = user_info['response']['name']
    social_email = user_info['response']['email']
    social_phone =  user_info['response']['mobile']
    social_password = "naver"
    result  = mysql.social_check(social_name, social_email, social_phone, social_password)
    if len(str(result)) != 0:
        session['is_loged_in'] = True
        session['username'] = social_name
        return redirect('/')
    print(result)
    return redirect('/')

# Google 로그인
@app.route('/google')
def googlelogin():
    google = google.create_client('google')  # create the google oauth client
    redirect_uri = url_for('authorize', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/authorize')
def authorize():
    google = google.create_client('google')  # create the google oauth client
    token = google.authorize_access_token()  # Access token from google (needed to get user info)
    resp = google.get('userinfo')  # userinfo contains stuff u specificed in the scrope
    user_info = resp.json()
    user = oauth.google.userinfo()  # uses openid endpoint to fetch user info
    print(f'user: {user}')
    social_name = user['name']
    social_email = user['email']
    print(social_email)
    social_phone = None
    social_password = 'google'
    result  = mysql.social_check(social_name, social_email, social_phone, social_password)
    if len(str(result)) != 0:
        session['is_loged_in'] = True
        session['username'] = social_name
        db = pymysql.connect(host=mysql.host, user=mysql.user, db=mysql.db, password=mysql.password, charset=mysql.charset)
        curs = db.cursor()

        sql = f'SELECT * FROM user WHERE email = %s;'
        curs.execute(sql , social_email)
        result = curs.fetchone()
        print(result[3])
        if result[3] == None:
            return render_template('add.html', email=social_email)
        else:
            return redirect('/')

@app.route('/update_phone' , methods=['GET', 'POST'])
def update():
    email = request.form.get("email")
    phone = request.form.get("phone")
    mysql.additional_info(email, phone)
    return redirect('/')

# 카카오 로그인 - 추후 추가 예정
@app.route('/kakao')
def kakao_login():
    return kakao.authorize_redirect(redirect_uri=url_for('kakao_callback', _external=True))

@app.route('/kakao-callback')
def kakao_callback():
    kakao_token = kakao.authorize_access_token()
    user_info = kakao.get('user').json()
    user = oauth.kakao.userinfo()
    print(user)
    # social_name = user['name']
    # social_email = user['email']
    # social_phone =  user['mobile']
    # social_password = "kakao"
    # result  = mysql.social_check(social_name, social_email, social_phone, social_password)
    # if len(str(result)) != 0:
    #     session['is_loged_in'] = True
    #     session['username'] = social_name
    #     return redirect('/')
    # print(result)
    # return redirect('/')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/test')
@is_loged_in
def test():
    return render_template('test.html')

@app.route('/result', methods=['GET', 'POST'])
@is_loged_in
def result():
    return render_template('result.html')

if __name__ == '__main__':
    app.run(debug=True)