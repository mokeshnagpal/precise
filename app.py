from flask import Flask, render_template, request, redirect, session, jsonify
from flask_session import Session
from firebase_admin import initialize_app, credentials, firestore
from bcrypt import checkpw, hashpw, gensalt
from regex import match
from numpy import full
from flask_mail import Mail, Message
from datetime import datetime, timedelta
from uuid import uuid4

website_name = "precise"
website_link = f'{website_name}.onrender.com'

app = Flask(__name__)

# Session configuration
app.config['SESSION_TYPE'] = 'filesystem'

# Email configuration for Flask-Mail using Gmail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'aarnanagpal@gmail.com'
app.config['MAIL_PASSWORD'] = 'zumfuvcevvyvowdc'

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(True)

mail = Mail(app)
Session(app)  # Initialize Flask-Session

# Firebase initialization
cred = credentials.Certificate({
  "type": "service_account",
  "project_id": "ai-based-traffic-managem-f30b3",
  "private_key_id": API_KEY,
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC8fJQAd/1d6zsJ\n+k+OmTPtcYBIumSEuGQLHiZCcT/1IBv/sJQCKHoomDLz3OIoRvkg1tNpEW/YuWCL\n4qs/pkCrS75dfsHVOsvhokgAq5GOQDFlj8/0FFz4lOnBVnCcnL0GjidWiX1ZKwwB\nOjoO2dsokOizgixxIGhempFKQ3pc7lgyKFjuixBh+30qebNny75GQB3YBhTC17VV\nWB2QRDmJD6wYYwdNYcYTVGO4U1w3dqmLKJliwv0A6KC11sePERy9Ptw2mUPRgJJu\nuDoUrcIU86VYvjxjCb9+bcXWvV/smX7RHZQ0BqNw0ge/UWucJnTC8lEo11ZPAAij\n0H5SaFQ3AgMBAAECggEAD6mTINYtAyS8s1pjSa2ttMw1hUBGgbLSzrZde9ruSMpi\nGTqilJVUJVMUX32aJg+pEaitnkb5J3tWrE5pvYXCokP5Lcq5L6Si9Ce92km8yXhz\nF7CTbqxR127ZsnD3iu6z/xCemzXHPpAcVMPHtvE1IWdSjDbDxk4TmNI47YCy8SLQ\n5odENLA7MGmyREJJ8bILwJZlT13KKl0v9a+rm+oWji0aPruA/L2231gx6RXoG0R5\ncYBkJP9k6YifzwiQ5CUuKr3yzEvY0BBWmOjGypgVAiFTa3WnicBGWWZF67b9coYm\n2DebzQXsEbfrdyJcJP9xzEA2Z/m5QyabU2lw+NtsOQKBgQD9f/AdV5N8r+ofJVG1\nC4oUexw9HBdIijKgoHctvP8abRLU3PeqROy5h2sEw8mxYUxltzBXXJE7eIK9wzkg\nBinnNj11L1hPWjia+teX4S8yiEm/y2TXlSp3fuYck5KagALdCDjuYLtFMbHNzrFv\nYeFJRAC2LPsfvELjTQd520HAyQKBgQC+WH0IxJV545a4wZ5B2XrD6INxZeUWyPm2\nT8/x78l5opa9/xCGZZJIbLXkfjHgvz6kGjVGmttNzS1r0CoggEIRy/ohQ6EU//17\nZsag5hnZJZb/OJLonsdPYMzds2lk+lhwLGuFmk1Ih6kPJuOB8SD1o3gEwnTysOym\nIiOPpLDs/wKBgDS8ovVXvMUZy7kDCIaDigxMuEk2SNm8dl/YQjLvuJqEyoAiIBv6\nDs1iEK+DE7ilJ0GZ5KKoDUa0AW786CtzXNBPBmYUnWiUumXzfVqJbEo09DLEW4xF\n6fnGGpUjVkJyEyZsiXt+ADea6QSJ1Xv4fufBD+zWWr/1aGzlH4MITBuRAoGAepDQ\nMk0jUxFRhDZoiU5Y1r1ppiNOmJVg9hv+cnNM8J3ZIw6SvXe58hjOJwt7YpTC6ThX\nBdfBTx/HF507AyKTaJJHxhOeLb+IoWVUkVaZXlHuIPl034UeIebbBAb63qK1P8Xa\nlnT9Pq7cFX2dEZcK+iEAr0/nrj5uo6tn6p7JrlECgYAonsqJ1Qk4OR4RYvL+eLhx\nG40EI8y/o/vqsf9dtD5pn+W0ru37nrgfN5ZmSE8QuWcqETJtLnb2p0Jo6Cg7epIh\n97fwmPySXriCA2ZzAwoZxl3eh28YmYDFrl+AxC2XrDCSSiN8JYF1nZVkAGzCSzE2\nK5AHdtjZzDJnj02Sb5ckng==\n-----END PRIVATE KEY-----\n",
  "client_email": "firebase-adminsdk-pf2xa@ai-based-traffic-managem-f30b3.iam.gserviceaccount.com",
  "client_id": "112093004985562674312",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-pf2xa%40ai-based-traffic-managem-f30b3.iam.gserviceaccount.com",
  "universe_domain": "googleapis.com"
})
initialize_app(cred)

db = firestore.client()  # Firestore client

node = 9
signal = 4
values = full((node, signal), {}, dtype=object)  # Matrix to store node and signal values

def validate_email(email):
    # Validates email using regex for stricter checking
    return bool(match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", email))

def validate_password(password):
    # Validates password based on given criteria
    if len(password) < 8 or not any(char.isupper() for char in password) or not any(char.islower() for char in password) or not any(char in "!@#$%^&*()-_+=[]{}|:<>?,./" for char in password):
        return False
    return True

def send_email(email, token):
    # Sends an email for account activation
    msg = Message('Validate yourself', sender=app.config['MAIL_USERNAME'], recipients=[email])
    msg.html = f'''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Email Verification</title>
        <style>
            body {{
                font-family: 'Arial', sans-serif;
                margin: 0;
                padding: 0;
                background-color: #f4f4f4;
            }}
            .container {{
                max-width: 600px;
                margin: 20px auto;
                background-color: #ffffff;
                padding: 20px;
                border-radius: 5px;
                box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            }}
            .header, .content, .footer {{
                text-align: center;
                margin-bottom: 20px;
            }}
            .footer {{
                font-size: 12px;
                color: #999;
            }}
            .btn-container {{
                text-align: center;
            }}
            .btn {{
                display: inline-block;
                padding: 10px 20px;
                background-color: #3498db;
                text-decoration: none;
                border-radius: 3px;
                color: #ffffff !important;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h2>Email Verification</h2>
            </div>
            <div class="content">
                <p>Dear User,</p>
                <p>You are verifying your email address for registration on <strong>P.R.E.C.I.S.E - Predictive Road Efficiency through Camera-Integrated Surveillance and Evaluation</strong> website.</p>
                <p>Please verify your identity by clicking the button below to activate your account. The link is valid for 10 minutes.</p>
                <div class="btn-container">
                    <a class="btn" href="https://{website_link}/email_response?token={token}&email={email}">Activate Your Account</a>
                </div>
            </div>
            <div class="footer">
                <p>If you did not request this verification, please ignore this email.</p>
                <p>This email was sent because you registered on our website. Contact our support team for any questions.</p>
            </div>
        </div>
    </body>
    </html>
    '''
    mail.send(msg)

@app.route('/logout')
def logout():
    # Logs out the user by removing 'logged_in' key from session
    session.pop('logged_in', None)
    return render_template('login.html', error="Logged out successfully.")

@app.route('/', methods=['GET', 'POST'])
def home():            
    if 'logged_in' in session and session['logged_in']:
        return render_template('control.html', session=1)
    else:
        return render_template('index.html', session=0)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    # Handles user signup
    error = ""
    if request.method == 'POST':
        seven_days_ago = datetime.now() - timedelta(days=7)
        query = db.collection('users').where('active', '==', 0).where('time', '>', seven_days_ago).get()

        for doc in query:
            db.collection('users').document(doc.id).delete()

        email = request.form['email']

        if not validate_email(email):
            error = 'Invalid email address.'
        else:
            user_email = db.collection('users').document(email).get().to_dict()
            if user_email and user_email['active'] == 0:
                error = 'Email-Id already exists.'
            else:
                token = str(uuid4().hex)
                db.collection('users').document(email).set({
                    'active': 0,
                    'time': datetime.now(),
                    'token': token
                })
                send_email(email, token)
                return render_template('login.html', error="Please validate your email by clicking on the link sent.")

    return render_template('signup.html', error=error)

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Handles user login
    error = ""
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        if not validate_email(email):
            error = 'Invalid email address.'
        elif not validate_password(password):
            error = 'Password not in proper format.'
        else:
            user_email = db.collection('users').document(email).get().to_dict()

            if user_email and user_email['active'] == 1:
                hashed_password = db.collection('users').document('password').get().to_dict()['password']
                if checkpw(password.encode(), hashed_password):
                    session['logged_in'] = True
                    return redirect('/')
                else:
                    error = 'Incorrect password.'
            else:
                error = 'User does not exist.'

    return render_template('login.html', error=error)
@app.route('/security', methods=['GET', 'POST'])
def security():
    error = ""
    if request.method == 'POST':
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if not validate_password(old_password):
            error = 'Invalid old password format.'
        elif not validate_password(new_password):
            error = 'Invalid new password format.'
        elif new_password != confirm_password:
            error = 'New password and confirm password do not match.'
        else:
            password = db.collection('users').document('password').get().to_dict()
            if password and checkpw(new_password.encode(), password['password']):
                error = 'New password cannot be the same as the old password.'
            elif password and checkpw(old_password.encode(), password['password']):
                hashed_password = hashpw(new_password.encode(), gensalt())
                db.collection('users').document('password').update({
                    'password': hashed_password
                })
                return render_template('security.html', error="Password updated successfully.")
            else:
                error = 'Old password does not match.'

    return render_template('security.html', error=error)
    
@app.route('/remove_session', methods=['POST'])
def remove_session():
    # Removes 'logged_in' key from session 
    session.pop('logged_in', None)
    return jsonify({'success': True})

@app.route('/email_response', methods=['GET'])
def email_response():
    # Handles email verification response
    if request.method == 'GET':
        token = request.args.get('token')
        email = request.args.get('email')
        
        user_email = db.collection('users').document(email).get().to_dict()
        if user_email and user_email['active'] == 0:
            if user_email["token"] == token:
                db.collection('users').document(email).update({
                    'active': 1,
                    'time': datetime.now(),
                    'token': ""
                })
                error = "Account activated."
            else:
                error = "Account not activated or already activated."
        else:
            error = "Account not found."
        return render_template('login.html', error=error)
    

if __name__ == '__main__':
    app.run(debug=True)


