import os
import os
import logging
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from dotenv import load_dotenv
import google.generativeai as genai
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from flask_mail import Mail, Message
from authlib.integrations.flask_client import OAuth



# Configure logging
logging.basicConfig(level=logging.DEBUG)

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT') or 587)
app.config['MAIL_USE_TLS'] = (os.environ.get('MAIL_USE_TLS') or 'true').lower() in ['true', 'on', '1']
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER')
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['GOOGLE_CLIENT_ID'] = os.environ.get('GOOGLE_CLIENT_ID')
app.config['GOOGLE_CLIENT_SECRET'] = os.environ.get('GOOGLE_CLIENT_SECRET')

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
mail = Mail(app)
oauth = OAuth(app)

google = oauth.register(
    name='google',
    client_id=app.config["GOOGLE_CLIENT_ID"],
    client_secret=app.config["GOOGLE_CLIENT_SECRET"],
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile'
    }
)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

genai.configure(api_key=os.environ["GEMINI_API_KEY"])

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    profile_image = db.Column(db.String(150), nullable=False, default='default.jpg')
    dreams = db.relationship('Dream', backref='author', lazy=True)

tags = db.Table('tags',
    db.Column('tag_id', db.Integer, db.ForeignKey('tag.id'), primary_key=True),
    db.Column('dream_id', db.Integer, db.ForeignKey('dream.id'), primary_key=True)
)

class Tag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

class Mood(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

class Dream(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    dream_text = db.Column(db.String(500), nullable=False)
    interpretation = db.Column(db.String(1000), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    tags = db.relationship('Tag', secondary=tags, lazy='select',
        backref=db.backref('dreams', lazy=True))
    mood_id = db.Column(db.Integer, db.ForeignKey('mood.id'), nullable=True)
    mood = db.relationship('Mood', backref='dreams')

    def to_dict(self):
        return {
            'id': self.id,
            'dream_text': self.dream_text,
            'interpretation': self.interpretation,
            'tags': [{'name': tag.name} for tag in self.tags],
            'mood': {'name': self.mood.name} if self.mood else None
        }

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def landing():
    return render_template('landing.html')

@app.route('/welcome')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/dashboard')
@login_required
def dashboard():
    dreams = current_user.dreams
    moods = Mood.query.all()
    return render_template('dashboard.html', history=dreams, moods=moods)

@app.route('/login/google')
def login_google():
    redirect_uri = url_for('authorize_google', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/authorize/google')
def authorize_google():
    token = google.authorize_access_token()
    user_info = google.get('https://www.googleapis.com/oauth2/v2/userinfo').json()
    
    user = User.query.filter_by(email=user_info['email']).first()
    if not user:
        new_user = User(
            email=user_info['email'],
            username=user_info.get('name', user_info['email'].split('@')[0]),
            password=generate_password_hash(os.urandom(16).hex(), method='pbkdf2:sha256'),
            profile_image=user_info.get('picture', 'default.jpg')
        )
        db.session.add(new_user)
        db.session.commit()
        user = new_user

    login_user(user)
    return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        user_by_username = User.query.filter_by(username=username).first()
        if user_by_username:
            flash('Username already exists.')
            return redirect(url_for('signup'))

        user_by_email = User.query.filter_by(email=email).first()
        if user_by_email:
            flash('Email address already registered.')
            return redirect(url_for('signup'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully! Please log in.')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('landing'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        if 'profile_picture' in request.files:
            file = request.files['profile_picture']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                # To avoid overwrites, prepend user id to filename
                filename = str(current_user.id) + '_' + filename
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                current_user.profile_image = filename
                db.session.commit()
                flash('Your profile picture has been updated.')
                return redirect(url_for('profile'))

        if 'update_profile' in request.form:
            new_username = request.form['username']
            new_email = request.form['email']

            if new_username != current_user.username:
                if User.query.filter(User.id != current_user.id, User.username == new_username).first():
                    flash('Username already exists.')
                    return redirect(url_for('profile'))
                current_user.username = new_username

            if new_email != current_user.email:
                if User.query.filter(User.id != current_user.id, User.email == new_email).first():
                    flash('Email already registered.')
                    return redirect(url_for('profile'))
                current_user.email = new_email
            
            db.session.commit()
            flash('Your profile has been updated.')
            return redirect(url_for('profile'))

        elif 'change_password' in request.form:
            current_password = request.form['current_password']
            new_password = request.form['new_password']

            if not check_password_hash(current_user.password, current_password):
                flash('Incorrect current password.')
                return redirect(url_for('profile'))

            current_user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
            db.session.commit()
            flash('Your password has been changed successfully.')
            return redirect(url_for('profile'))

    return render_template('profile.html')

@app.route('/all_dreams')
def all_dreams():
    dreams = Dream.query.all()
    return render_template('all_dreams.html', dreams=dreams)

@app.route('/interpret', methods=['POST'])
@login_required
def interpret():
    dream_text = request.form['dream']
    tags_string = request.form.get('tags', '')
    mood_id = request.form.get('mood')
    language = request.form.get('language', 'English')  # Default to English
    if not dream_text:
        return jsonify({'error': 'Please enter a dream.'}), 400
    if not mood_id:
        return jsonify({'error': 'Please select a mood.'}), 400

    try:
        model = genai.GenerativeModel('gemini-1.5-flash-latest')
        prompt = f"User '{current_user.username}' had a dream: '{dream_text}'. As a dream interpreter, use your knowledge and web search to analyze this dream in {language}. Provide a short interpretation (around 50 words) and then list the key symbols and their possible meanings based on your search. Finally, give a one-sentence summary of the dream's potential message."
        response = model.generate_content(prompt)
        interpretation = ''.join([part.text for part in response.parts])
        new_dream = Dream(dream_text=dream_text, interpretation=interpretation, author=current_user)
        if mood_id:
            new_dream.mood_id = mood_id

        if tags_string:
            tag_names = [name.strip() for name in tags_string.split(',')]
            for name in tag_names:
                tag = Tag.query.filter_by(name=name).first()
                if not tag:
                    tag = Tag(name=name)
                    db.session.add(tag)
                new_dream.tags.append(tag)

        db.session.add(new_dream)
        db.session.commit()
        flash(f'Your dream has been interpreted! Check your dashboard.')
        return jsonify({'interpretation': interpretation, 'history': [d.to_dict() for d in current_user.dreams]})
    except Exception as e:
        logging.error(f"Error during dream interpretation: {e}")
        return jsonify({'error': str(e)}), 500

@app.cli.command("init-moods")
def init_moods():
    """Initialize the moods in the database."""
    moods = ['Happy', 'Sad', 'Anxious', 'Excited', 'Scared', 'Confused']
    for mood_name in moods:
        if not Mood.query.filter_by(name=mood_name).first():
            db.session.add(Mood(name=mood_name))
    db.session.commit()
    print("Moods initialized.")

@app.route('/api/history')
@login_required
def api_history():
    return jsonify([d.to_dict() for d in current_user.dreams])

@app.route('/delete_dream/<int:dream_id>', methods=['POST'])
@login_required
def delete_dream(dream_id):
    dream = Dream.query.get_or_404(dream_id)
    if dream.author != current_user:
        return jsonify({'error': 'Unauthorized'}), 403
    db.session.delete(dream)
    db.session.commit()
    return jsonify({'result': 'success'})

@app.route('/analytics')
@login_required
def analytics():
    return render_template('analytics.html')

@app.route('/advanced_analytics')
@login_required
def advanced_analytics():
    return render_template('advanced_analytics.html')

@app.route('/api/analytics')
@login_required
def api_analytics():
    dreams = current_user.dreams
    total_dreams = len(dreams)

    # Word frequency
    all_words = ' '.join([d.dream_text for d in dreams]).split()
    word_counts = {}
    for word in all_words:
        word_counts[word] = word_counts.get(word, 0) + 1
    sorted_words = sorted(word_counts.items(), key=lambda x: x[1], reverse=True)

    # Mood frequency
    mood_counts = {}
    for dream in dreams:
        if dream.mood:
            mood_counts[dream.mood.name] = mood_counts.get(dream.mood.name, 0) + 1

    # Tag frequency
    tag_counts = {}
    for dream in dreams:
        for tag in dream.tags:
            tag_counts[tag.name] = tag_counts.get(tag.name, 0) + 1

    return jsonify({
        'total_dreams': total_dreams,
        'common_words': sorted_words[:10],
        'mood_distribution': mood_counts,
        'tag_cloud': tag_counts
    })

@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            token = s.dumps(user.email, salt='password-reset-salt')
            msg = Message('Password Reset Request', recipients=[user.email])
            msg.body = f'''To reset your password, visit the following link:
{url_for('reset_password', token=token, _external=True)}

If you did not make this request then simply ignore this email and no changes will be made.
'''
            mail.send(msg)
            flash('An email has been sent with instructions to reset your password.')
        else:
            flash('Email address not found.')
        return redirect(url_for('reset_password_request'))
    return render_template('reset_password_request.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=3600)
    except SignatureExpired:
        flash('The password reset link has expired.')
        return redirect(url_for('reset_password_request'))
    except Exception:
        flash('Invalid password reset link.')
        return redirect(url_for('reset_password_request'))

    if request.method == 'POST':
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user:
            user.password = generate_password_hash(password, method='pbkdf2:sha256')
            db.session.commit()
            flash('Your password has been updated.')
            return redirect(url_for('login'))
    return render_template('reset_password.html', token=token)


@app.cli.command('init-db')
def init_db_command():
    """Creates the database tables."""
    with app.app_context():
        db.create_all()
    print('Initialized the database.')
from flask import send_from_directory

@app.route('/google481220b0344d2cd7.html')
def google_verification():
    return send_from_directory('.', 'google481220b0344d2cd7.html')
