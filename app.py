import os
from flask import Flask, request, jsonify, Response, render_template,render_template_string, url_for, redirect
from flask import Flask,redirect,render_template, jsonify, render_template_string, Response
from markupsafe import escape
from flask import request
from flask import Flask
from flask import jsonify
from flask import request, session
import base64
from werkzeug.utils import secure_filename
import os
from bson import ObjectId
from datetime import datetime
from ultralytics import YOLO
from ultralytics.solutions import object_counter
import cv2
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from flask_dance.contrib.google import make_google_blueprint, google
from flask_mail import Mail, Message
from flask_jwt_extended import JWTManager, create_access_token, decode_token
from flask_httpauth import HTTPBasicAuth
from dotenv import load_dotenv
from bson.objectid import ObjectId
import uuid
import secrets
import datetime
import locale
from flask_cors import CORS
from shapely.geometry import Polygon, Point

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['MONGO_URI'] = os.getenv('MONGO_URI')
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'restcountzy@gmail.com' #ganti pake email sendiri
app.config['MAIL_PASSWORD'] = 'sdspgsziglytwpig' 
app.config["JWT_SECRET_KEY"] = os.getenv('JWT_SECRET_KEY')
app.config['MAIL_DEFAULT_SENDER'] = 'restcountzy@gmail.com' #ganti pake email sendiri

mongo = PyMongo(app)
model = YOLO("model/restcount.pt")
locale.setlocale(locale.LC_TIME, 'id_ID.UTF-8')
bcrypt = Bcrypt(app)
mail = Mail(app)
jwt = JWTManager(app)
auth = HTTPBasicAuth()
login_manager = LoginManager(app)
login_manager.login_view = 'login'

CORS(app)

google_bp = make_google_blueprint(client_id=os.getenv('GOOGLE_CLIENT_ID'), client_secret=os.getenv('GOOGLE_CLIENT_SECRET'), redirect_to='google_login')
app.register_blueprint(google_bp, url_prefix='/login')

# Define the collection
predictions_collection = mongo.db.predictions
counts_collection = mongo.db.counts

# Inisialisasi YOLO model dan object counter
region_of_interest = [(300, 20), (302, 680), (280, 680), (280, 20)]
counter = object_counter.ObjectCounter(classes_names=model.names, view_img=True, reg_pts=region_of_interest, draw_tracks=True)

class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data['_id'])  # Convert ObjectId to string
        self.username = user_data['username']
        self.email = user_data['email']
        self.is_verified = user_data.get('is_verified', False)
        self.api_key = user_data.get('api_key')

    @staticmethod
    def create_user(username, email, password=None, google_id=None):
        user = {
            "username": username,
            "email": email,
            "password": bcrypt.generate_password_hash(password).decode('utf-8') if password else None,
            "google_id": google_id,
            "is_verified": False,
            "api_key": secrets.token_hex(16)
        }
        result = mongo.db.users.insert_one(user)
        user['_id'] = str(result.inserted_id)  # Convert ObjectId to string
        return user

    @staticmethod
    def find_by_email(email):
        return mongo.db.users.find_one({"email": email})

    @staticmethod
    def find_by_google_id(google_id):
        return mongo.db.users.find_one({"google_id": google_id})

    @staticmethod
    def verify_password(stored_password, provided_password):
        return bcrypt.check_password_hash(stored_password, provided_password)

    @staticmethod
    def set_verified(user_id):
        mongo.db.users.update_one({'_id': ObjectId(user_id)}, {'$set': {'is_verified': True}})

    def update_password(self, new_password):
        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        mongo.db.users.update_one({'_id': ObjectId(self.id)}, {'$set': {'password': hashed_password}})

@login_manager.user_loader
def load_user(user_id):
    user = mongo.db.users.find_one({"_id": ObjectId(user_id)})
    return User(user) if user else None

@auth.verify_password
def verify_password(email, password):
    user_data = User.find_by_email(email)
    if user_data and User.verify_password(user_data['password'], password):
        return User(user_data)
    return None

def verify_api_key(api_key):
    user_data = mongo.db.users.find_one({"api_key": api_key})
    if user_data:
        return User(user_data)
    return None

def decodetoken(jwtToken):
    decode_result = decode_token(jwtToken)
    return decode_result

def save_to_mongodb(predictions, location, counts):
    current_date = datetime.datetime.now().strftime('%d-%m-%Y')
    current_time = datetime.datetime.now().strftime('%H:%M:%S')
    day_of_week = datetime.datetime.now().strftime('%A')

    for result in predictions:
        if result.boxes is not None and len(result.boxes) > 0:
            for pred in result.boxes[0]:
                class_index = int(pred.cls[0])
                class_name = model.names[class_index]

                # Insert prediction into MongoDB
                predictions_collection.insert_one({
                    'label': class_name,
                    'tanggal': current_date,
                    'hari': day_of_week,
                    'waktu': current_time,
                    'location': location
                })

    # Save counts to MongoDB
    counts_collection.insert_one({
        'counts': counts,
        'tanggal': current_date,
        'location': location
    })


# Define ROI and Object Counter
region_of_interest = [(20, 300), (830, 302), (830, 280), (0, 280)]
classes_names = model.names  # Assuming model.names provides the classes names as a list
counter = object_counter.ObjectCounter(classes_names=classes_names, view_img=True, reg_pts=region_of_interest, draw_tracks=True)

lokasi = ""

# Realtime Object Detection & Counting
@app.route('/')
def index():
    return render_template('video.html')

@app.route('/video_feed', methods=['GET', 'POST'])
def video_feed():
    location = request.form.get('location')
    if location:
        return Response(count_objects(location), mimetype='multipart/x-mixed-replace; boundary=frame')
    return redirect(url_for('index'))

def count_objects(location):
    cap = cv2.VideoCapture('data/jalan2.mp4')
    assert cap.isOpened()
    tracked_ids = set()
    
    while True:
        success, frame = cap.read()
        if not success:
            break
        
        # Detect and track objects
        results = model.track(frame, persist=True, show=False)
        frame = counter.start_counting(frame, results)

        for result in results:
            if result.boxes.id is not None:
                boxes = result.boxes.xyxy.cpu()
                clss = result.boxes.cls.cpu().tolist()
                track_ids = result.boxes.id.int().cpu().tolist()

                for box, track_id, cls in zip(boxes, track_ids, clss):
                    if track_id not in tracked_ids:
                        prev_position = counter.track_history[track_id][-2] if len(counter.track_history[track_id]) > 1 else None
                        current_position = (float((box[0] + box[2]) / 2), float((box[1] + box[3]) / 2))

                        if len(region_of_interest) >= 3:
                            counting_region = Polygon(region_of_interest)
                            is_inside = counting_region.contains(Point(current_position))

                            if prev_position and is_inside:
                                tracked_ids.add(track_id)
                                now = datetime.datetime.now()
                                date = now.date().isoformat()
                                day_name = now.strftime('%A')
                                counts = {model.names[cls]: 1}

                                # Save to MongoDB
                                counts_collection.update_one(
                                    {'date': str(date), 'day': day_name, 'location': location},
                                    {'$inc': {f'counts.{key}': value for key, value in counts.items()},
                                    '$setOnInsert': {'date': str(date), 'day': day_name, 'location': location}},
                                    upsert=True
                                )

        ret, buffer = cv2.imencode('.jpg', frame)
        frame = buffer.tobytes()
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')
    
    cap.release()

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not email or not password:
        return jsonify({"message": "Missing username, email, or password"}), 400

    existing_user = User.find_by_email(email)
    if existing_user:
        if existing_user.get('is_verified', False):
            return jsonify({"message": "Email already registered"}), 400
        else:
            # Resend verification email
            token = create_access_token(identity=str(existing_user['_id']), expires_delta=False)
            msg = Message('Email Verification', recipients=[email])
            msg.body = f'Your verification link is: {token}'
            mail.send(msg)
            return jsonify({"message": "Verification email sent. Please check your inbox."}), 200

    user_data = User.create_user(username=username, email=email, password=password)

    # Send verification email
    token = create_access_token(identity=user_data['_id'], expires_delta=False)
    msg = Message('Email Verification', recipients=[email])
    msg.body = f'Your verification link is: {token}'
    mail.send(msg)

    return jsonify({"message": "User registered successfully. Verification email sent."}), 201

@app.route('/auth', methods=['GET'])
def detail_user():
    bearer_auth = request.headers.get('Authorization', None)
    if not bearer_auth:
        return {"message": "Authorization header missing"}, 401

    try:
        jwt_token = bearer_auth.split()[1]
        token = decode_token(jwt_token)
        username = token.get('sub')

        if not username:
            return {"message": "Token payload is invalid"}, 401

        user = mongo.db.users.find_one({"_id": ObjectId(username)})
        if not user:
            return {"message": "User not found"}, 404

        # Update is_verified to True
        mongo.db.users.update_one({"_id": user["_id"]}, {"$set": {"is_verified": True}})

        data = {
            'username': user['username'],
            'email': user['email'],
            '_id': str(user['_id'])  # Convert ObjectId to string
        }
    except Exception as e:
        return {
            'message': f'Token is invalid. Please log in again! {str(e)}'
        }, 401

    return jsonify(data), 200

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    user_data = User.find_by_email(email)
    if user_data and User.verify_password(user_data['password'], password):
        if not user_data.get('is_verified'):
            return jsonify({"message": "Email not verified"}), 403
        user = User(user_data)
        login_user(user)
        return jsonify({"message": "Login successful"}), 200
    return jsonify({"message": "Invalid credentials"}), 401

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({"message": "Logged out successfully"}), 200

@app.route('/update_password', methods=['POST'])
@login_required
def update_password():
    try:
        data = request.json
        current_password = data.get('Password lama')
        new_password = data.get('Password baru')

        if not current_password or not new_password:
            return jsonify({"message": "Missing current password or new password"}), 400

        user_data = mongo.db.users.find_one({"_id": ObjectId(current_user.id)})
        if not user_data:
            return jsonify({"message": "User not found"}), 404

        if not User.verify_password(user_data['password'], current_password):
            return jsonify({"message": "Current password is incorrect"}), 401

        current_user.update_password(new_password)
        return jsonify({"message": "Password updated successfully"}), 200

    except Exception as e:
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500

@app.route('/edit_profile', methods=['POST'])
@login_required
def edit_profile():
    try:
        data = request.form
        username = data.get('username')
        photo = request.files.get('photo')

        if not username:
            return jsonify({"message": "Missing username"}), 400

        user_data = mongo.db.users.find_one({"_id": ObjectId(current_user.id)})
        if not user_data:
            return jsonify({"message": "User not found"}), 404

        update_data = {
            'username': username
        }

        if photo:
            projectPath = "/home/student/21090007/flask/"
            photo_filename = f"{secrets.token_hex(16)}.jpg"
            photo.save(os.path.join(projectPath, 'upload', photo_filename))
            update_data['photo'] = photo_filename

        mongo.db.users.update_one({'_id': ObjectId(current_user.id)}, {'$set': update_data})

        return jsonify({"message": "Profile updated successfully"}), 200

    except Exception as e:
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500

@app.route('/change_email', methods=['POST'])
@login_required
def change_email():
    try:
        data = request.json
        new_email = data.get('new_email')

        if not new_email:
            return jsonify({"message": "Missing new email"}), 400

        user_data = mongo.db.users.find_one({"_id": ObjectId(current_user.id)})
        if not user_data:
            return jsonify({"message": "User not found"}), 404

        # Send email confirmation
        token = create_access_token(identity=str(current_user.id), expires_delta=False)
        msg = Message('Email Change Confirmation', recipients=[new_email])
        msg.body = f'Your email change confirmation token is: {token}'
        mail.send(msg)

        return jsonify({"message": "Email change confirmation sent. Please check your inbox."}), 200

    except Exception as e:
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500

@app.route('/confirm_change_email', methods=['POST'])
def confirm_change_email():
    bearer_auth = request.headers.get('Authorization', None)
    if not bearer_auth:
        return {"message": "Authorization header missing"}, 401

    try:
        jwt_token = bearer_auth.split()[1]
        token = decode_token(jwt_token)
        user_id = token.get('sub')

        if not user_id:
            return {"message": "Token payload is invalid"}, 401

        user = mongo.db.users.find_one({"_id": ObjectId(user_id)})
        if not user:
            return jsonify({"message": "User not found"}), 404

        # Update email verification status or perform other necessary actions
        mongo.db.users.update_one({"_id": ObjectId(user_id)}, {"$set": {"is_email_verified": True}})
        return jsonify({"message": "Email verification successful"}), 200

    except Exception as e:
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500

@app.route('/profile', methods=['GET'])
@login_required
def profile():
    try:
        user_data = mongo.db.users.find_one({"_id": ObjectId(current_user.id)})
        if not user_data:
            return jsonify({"message": "User not found"}), 404

        profile_data = {
            'username': user_data['username'],
            'email': user_data['email'],
            'photo': url_for('static', filename='uploads/' + user_data.get('photo', 'default_profile.jpg'))
        }

        return jsonify(profile_data), 200

    except Exception as e:
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500


@app.route('/forgot_password', methods=['POST'])
def forgot_password():
    data = request.json
    email = data.get('email')

    if not email:
        return jsonify({"message": "Missing email"}), 400

    user_data = User.find_by_email(email)
    if not user_data:
        return jsonify({"message": "User not found"}), 404

    # Kirim email reset password
    token = create_access_token(identity=str(user_data['_id']), expires_delta=False)
    msg = Message('Password Reset', recipients=[email])
    msg.body = f'Your password reset link is: {url_for("reset_password", token=token, _external=True)}'
    mail.send(msg)

    return jsonify({"message": "Password reset email sent. Please check your inbox."}), 200


@app.route('/google_login')
def google_login():
    if not google.authorized:
        return redirect(url_for('google.login'))

    resp = google.get('/oauth2/v1/userinfo')
    user_info = resp.json()

    user = User.find_by_google_id(user_info['id'])
    if not user:
        user = User.create_user(username=user_info['name'], email=user_info['email'], google_id=user_info['id'])

    login_user(User(user))
    return jsonify({"message": "Login successful"}), 200

if __name__ == '__main__':
    app.run(debug=True, host='192.168.0.119', port=5000)