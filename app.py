from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
import uuid
from datetime import datetime, timedelta
import hashlib

app = Flask(__name__)


# Replace 'your_username', 'your_password', 'your_host', and 'your_database'
# with your MySQL credentials and database information
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://FlashKis :fuck.you@FlashKis.mysql.pythonanywhere-services.com/FlashKiss'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class License(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(36), unique=True, nullable=False)
    valid_until = db.Column(db.DateTime, nullable=False)
    max_devices = db.Column(db.Integer, nullable=False)
    used_devices = db.Column(db.Integer, default=0)

    def __repr__(self):
        return f'<License {self.key}>'
    # Create the database tables
    db.create_all()

# Admin credentials
admin_username = "FlashKiss"
admin_password_hash = hashlib.sha256("fuck.you".encode()).hexdigest()

with app.app_context():
    db.create_all()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        if username == admin_username and password_hash == admin_password_hash:
            session['logged_in'] = True
            return redirect(url_for('index'))
        else:
            return "Invalid credentials", 401
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/generate_license', methods=['POST'])
@login_required
def generate_license():
    data = request.json
    key = data.get('key', str(uuid.uuid4()))
    valid_days = data.get('valid_days', 30)
    max_devices = data.get('max_devices', 1)
    valid_until = datetime.now() + timedelta(days=valid_days)
    
    new_license = License(key=key, valid_until=valid_until, max_devices=max_devices)
    db.session.add(new_license)
    db.session.commit()

    return jsonify({'key': key, 'valid_until': valid_until, 'max_devices': max_devices})

@app.route('/delete_license', methods=['POST'])
@login_required
def delete_license():
    data = request.json
    key = data.get('key')
    
    license = License.query.filter_by(key=key).first()
    if not license:
        return jsonify({'status': 'error', 'message': 'License key not found'}), 404
    
    db.session.delete(license)
    db.session.commit()
    
    return jsonify({'status': 'success', 'message': 'License key deleted'})

@app.route('/update_license', methods=['POST'])
@login_required
def update_license():
    data = request.json
    key = data.get('key')
    valid_days = data.get('valid_days')
    max_devices = data.get('max_devices')
    
    license = License.query.filter_by(key=key).first()
    if not license:
        return jsonify({'status': 'error', 'message': 'License key not found'}), 404
    
    if valid_days is not None:
        license.valid_until = datetime.now() + timedelta(days=valid_days)
    if max_devices is not None:
        license.max_devices = max_devices
    
    db.session.commit()
    
    return jsonify({'status': 'success', 'message': 'License key updated'})

@app.route('/get_licenses', methods=['GET'])
@login_required
def get_licenses():
    licenses = License.query.all()
    return jsonify([{
        'key': license.key,
        'valid_until': license.valid_until,
        'max_devices': license.max_devices,
        'used_devices': license.used_devices
    } for license in licenses])

if __name__ == '__main__':
    app.run(debug=True)
