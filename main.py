from functools import wraps
from quart import Quart, render_template, request, redirect, session, url_for, flash, jsonify, g, send_from_directory, abort
import uuid
import bcrypt
import os
import random
import string
import atexit
import time
import requests
import logging
import aiohttp
from logging.handlers import RotatingFileHandler
from fuzzywuzzy import fuzz
from cryptography.fernet import Fernet
from datetime import timedelta, datetime
from PIL import Image
from werkzeug.utils import secure_filename
from apscheduler.schedulers.background import BackgroundScheduler
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.decomposition import TruncatedSVD, NMF
from sklearn.metrics.pairwise import linear_kernel
from sklearn.exceptions import NotFittedError
from translations import translations
import aiosqlite

app = Quart(__name__)

RECAPTCHA_SECRET_KEY = ''
RECAPTCHA_SITE_KEY = ''
MAX_FAILED_ATTEMPTS = 3
CAPTCHA_REQUIRED_ATTEMPTS = 3

def load_or_generate_key():
    key_file = 'encryption.key'
    if os.path.exists(key_file):
        with open(key_file, 'rb') as f:
            key = f.read()
    else:
        key = Fernet.generate_key()
        with open(key_file, 'wb') as f:
            f.write(key)
    return key

encryption_key = load_or_generate_key()
cipher_suite = Fernet(encryption_key)

app.secret_key = os.urandom(24)

logger = logging.getLogger('my_app')
logger.setLevel(logging.INFO)

handler = RotatingFileHandler('app.log', maxBytes=10000, backupCount=1)
handler.setLevel(logging.INFO)

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)

logger.addHandler(handler)

app.config['SESSION_TYPE'] = 'aiosqlite'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=31)

app.config['MAX_CONTENT_LENGTH'] = 20 * 1024 * 1024

CACHE_DIR = 'cache/'

def get_cache_key(ip):
    return os.path.join(CACHE_DIR, f'{ip}.pkl')

async def get_file_cached_data(ip):
    cache_file = get_cache_key(ip)
    if os.path.exists(cache_file):
        with open(cache_file, 'rb') as f:
            return pickle.load(f)
    return None

async def cache_file_data(ip, data):
    if not os.path.exists(CACHE_DIR):
        os.makedirs(CACHE_DIR)
    cache_file = get_cache_key(ip)
    with open(cache_file, 'wb') as f:
        pickle.dump(data, f)

async def verify_recaptcha(token):
    payload = {
        'secret': RECAPTCHA_SECRET_KEY,
        'response': token
    }
    async with aiohttp.ClientSession() as session:
        async with session.post('https://www.google.com/recaptcha/api/siteverify', data=payload) as response:
            result = await response.json()
    return result.get('success')

def login_required(f):
    @wraps(f)
    async def decorated_function(*args, **kwargs):
        if 'userid' not in session:
            return redirect(url_for('login'))
        return await f(*args, **kwargs)
    return decorated_function

async def get_db_cached_data(ip, db):
    async with db.execute("SELECT data FROM cache WHERE ip=?", (ip,)) as cursor:
        row = await cursor.fetchone()
        return row[0] if row else None

async def cache_db_data(ip, data, db):
    async with db.execute("SELECT 1 FROM cache WHERE ip=?", (ip,)) as cursor:
        exists = await cursor.fetchone()
    if exists:
        await db.execute("UPDATE cache SET data=? WHERE ip=?", (data, ip))
    else:
        await db.execute("INSERT INTO cache (ip, data) VALUES (?, ?)", (ip, data))
    await db.commit()

async def get_db():
    if 'db' not in g:
        g.db = await aiosqlite.connect('instance/users.db')
        g.db.row_factory = aiosqlite.Row
    return g.db

@app.before_request
async def before_request():
    session_id = session.get('session_id')
    db = await get_db()
    if session_id:
        async with db.execute("SELECT * FROM session WHERE session_id=?", (session_id,)) as cursor:
            session_record = await cursor.fetchone()
        
        if session_record:
            expires_at_str = session_record['expires_at']
            try:
                if isinstance(expires_at_str, str):
                    expires_at = datetime.fromisoformat(expires_at_str)
                else:
                    expires_at = expires_at_str  
            except ValueError:
                expires_at = None  

            if not expires_at or expires_at < datetime.utcnow():
                logger.error(f"Invalid session ID {session_id} or session expired.")
                session.pop('session_id', None)
        else:
            logger.error("Session ID not found.")
            session.pop('session_id', None)
    else:
        logger.error("Session ID not found.")

blocked_ips = {}

async def is_ip_blocked(ip):
    if ip in blocked_ips:
        blocked_until = blocked_ips[ip]
        if time.time() < blocked_until:
            return True
        else:
            del blocked_ips[ip]
    return False

def block_ip(ip, duration=600):
    blocked_ips[ip] = time.time() + duration

async def get_cached_data(session_id, db):
    async with db.execute("SELECT data FROM cache WHERE session_id=?", (session_id,)) as cursor:
        row = await cursor.fetchone()
        return row[0] if row else None

async def cache_data(session_id, data, db):
    async with db.execute("SELECT 1 FROM cache WHERE session_id=?", (session_id,)) as cursor:
        exists = await cursor.fetchone()
    if exists:
        await db.execute("UPDATE cache SET data=? WHERE session_id=?", (data, session_id))
    else:
        await db.execute("INSERT INTO cache (session_id, data) VALUES (?, ?)", (session_id, data))
    await db.commit()

@app.route("/captcha", methods=["POST"])
async def validate_captcha():
    captcha_response = (await request.form).get('g-recaptcha-response')
    secret_key = os.getenv('RECAPTCHA_SECRET_KEY')
    payload = {
        'secret': secret_key,
        'response': captcha_response
    }
    response = await requests.post('https://www.google.com/recaptcha/api/siteverify', data=payload)
    result = response.json()
    
    if not result.get('success'):
        abort(400, description="Captcha verification failed")
    
    return jsonify({"message": "Captcha verification passed"})

@app.errorhandler(429)
async def ratelimit_error(e):
    return jsonify(error="Too many requests, please try again later."), 429

@app.before_request
async def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=30)

@app.context_processor
async def inject_user():
    return dict(current_user=g.current_user)

@app.teardown_appcontext
async def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        await db.close()

async def create_tables():
    db = await get_db()

    await db.execute('''
        CREATE TABLE IF NOT EXISTS user (
            id TEXT PRIMARY KEY,
            userid TEXT UNIQUE NOT NULL,
            nickname TEXT UNIQUE NOT NULL,
            avatar TEXT NOT NULL,
            password TEXT NOT NULL,
            subscription_status TEXT DEFAULT 'Free',
            verified_date DATETIME,
            is_verified BOOLEAN DEFAULT 0,
            is_admin BOOLEAN DEFAULT 0,
            is_banned BOOLEAN DEFAULT 0,
            preferred_language TEXT DEFAULT 'en',
            banner TEXT,
            terms_accepted DATETIME
        )
    ''')

    await db.execute('''
        CREATE TABLE IF NOT EXISTS post (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            postid TEXT UNIQUE NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            image TEXT,
            user_postid TEXT NOT NULL,
            likes_count INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_postid) REFERENCES user(userid) ON DELETE CASCADE
        )
    ''')

    await db.execute('''
        CREATE TABLE IF NOT EXISTS comment (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            content TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            user_id TEXT NOT NULL,
            post_id TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES user(userid) ON DELETE CASCADE,
            FOREIGN KEY(post_id) REFERENCES post(postid) ON DELETE CASCADE
        )
    ''')

    await db.execute('''
        CREATE TABLE IF NOT EXISTS user_likes (
            user_id TEXT NOT NULL,
            post_id TEXT NOT NULL,
            PRIMARY KEY(user_id, post_id),
            FOREIGN KEY(user_id) REFERENCES user(userid) ON DELETE CASCADE,
            FOREIGN KEY(post_id) REFERENCES post(postid) ON DELETE CASCADE
        )
    ''')

    await db.execute('''
        CREATE TABLE IF NOT EXISTS subscriptions (
            subscriber_id TEXT NOT NULL,
            subscribed_to_id TEXT NOT NULL,
            PRIMARY KEY(subscriber_id, subscribed_to_id),
            FOREIGN KEY(subscriber_id) REFERENCES user(userid) ON DELETE CASCADE,
            FOREIGN KEY(subscribed_to_id) REFERENCES user(userid) ON DELETE CASCADE
        )
    ''')

    await db.execute('''
        CREATE TABLE IF NOT EXISTS notification (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subscriber_id TEXT NOT NULL,
            subscribed_to_id TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(subscriber_id) REFERENCES user(userid) ON DELETE CASCADE,
            FOREIGN KEY(subscribed_to_id) REFERENCES user(userid) ON DELETE CASCADE
        )
    ''')

    await db.execute('''
        CREATE TABLE IF NOT EXISTS ip_address (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT UNIQUE NOT NULL,
            last_registration_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            registration_attempts INTEGER DEFAULT 0
        )
    ''')

    await db.execute('''
        CREATE TABLE IF NOT EXISTS ip_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            request_count INTEGER DEFAULT 0,
            last_request_time DATETIME DEFAULT CURRENT_TIMESTAMP,
            blocked_until DATETIME,
            UNIQUE(ip)
        )
    ''')

    await db.execute('''
        CREATE TABLE IF NOT EXISTS failed_login_attempt (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL,
            attempt_count INTEGER DEFAULT 0,
            last_attempt_time DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(ip_address)
        )
    ''')

    await db.execute('''
        CREATE TABLE IF NOT EXISTS session (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT UNIQUE NOT NULL,
            user_id TEXT NOT NULL,
            expires_at DATETIME NOT NULL,
            FOREIGN KEY(user_id) REFERENCES user(userid) ON DELETE CASCADE
        )
    ''')

    await db.execute('''
        CREATE TABLE IF NOT EXISTS cache (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT UNIQUE NOT NULL,
            data TEXT NOT NULL
        )
    ''')

    await db.commit()

@app.before_serving
async def startup():
    await create_tables()

async def update_session_table():
    db = await get_db()
    await db.execute('ALTER TABLE session ADD COLUMN user_id TEXT NOT NULL')
    await db.commit()

@app.route('/post/<postid>/comment', methods=['GET'])
async def get_comment(postid):
    db = await get_db()
    async with db.execute('''SELECT c.id, c.content, c.created_at, u.nickname, u.avatar, u.is_verified
                             FROM comment c
                             JOIN user u ON c.user_id = u.userid
                             WHERE c.post_id = ?''', (postid,)) as cursor:
        comments = await cursor.fetchall()

    comments_list = [{
        'id': comment['id'],
        'content': comment['content'],
        'created_at': datetime.strptime(comment['created_at'], "%Y-%m-%d %H:%M:%S").strftime("%Y-%m-%d %H:%M:%S"),
        'user_nickname': comment['nickname'],
        'user_avatar': comment['avatar'],
        'is_verified': comment['is_verified']
    } for comment in comments]

    return jsonify(comments_list)

@app.route('/post/<postid>/comments', methods=['GET'])
async def get_comments(postid):
    db = await get_db()
    async with db.execute('''SELECT c.id, c.content, c.created_at, u.nickname, u.avatar, u.is_verified, u.is_banned
                             FROM comment c
                             JOIN user u ON c.user_id = u.userid
                             WHERE c.post_id = ?''', (postid,)) as cursor:
        comments = await cursor.fetchall()

    comments_list = [{
        'id': comment['id'],
        'content': comment['content'],
        'created_at': datetime.strptime(comment['created_at'], "%Y-%m-%d %H:%M:%S").strftime("%Y-%m-%d %H:%M:%S"),
        'user_nickname': comment['nickname'],
        'user_avatar': url_for('static', filename='images/' + comment['avatar']),
        'is_verified': comment['is_verified'],
        'is_banned': comment['is_banned']
    } for comment in comments]

    return jsonify(comments_list)

@app.route('/add_comment', methods=['POST'])
@login_required
async def add_comment():
    data = await request.get_json()
    post_id = data.get('post_id')
    content = data.get('content')

    if not post_id or not content:
        return jsonify({'status': 'error', 'message': 'Invalid input'})

    if len(content) > 175:
        return jsonify({'status': 'error', 'message': 'Comment exceeds 175 characters limit'})

    db = await get_db()
    post = await db.execute('SELECT * FROM post WHERE postid=?', (post_id,))
    post = await post.fetchone()

    if not post:
        return jsonify({'status': 'error', 'message': 'Post not found'})

    user_id = session['userid']
    user = await db.execute('SELECT * FROM user WHERE userid=?', (user_id,))
    user = await user.fetchone()

    last_comment = await db.execute('''
        SELECT * FROM comment WHERE user_id=? AND post_id=?
        ORDER BY created_at DESC LIMIT 1
    ''', (user_id, post_id))
    last_comment = await last_comment.fetchone()

    if last_comment and datetime.utcnow() - last_comment['created_at'] < timedelta(seconds=60):
        return jsonify({'status': 'error', 'message': 'You are commenting too frequently. Please wait before posting another comment.'})

    new_comment = {
        'content': content,
        'user_id': user_id,
        'post_id': post_id,
        'created_at': datetime.utcnow()
    }
    await db.execute('''
        INSERT INTO comment (content, user_id, post_id, created_at)
        VALUES (:content, :user_id, :post_id, :created_at)
    ''', new_comment)
    await db.commit()

    comment_data = {
        'user_avatar': user['avatar'],
        'user_nickname': user['nickname'],
        'content': content,
        'created_at': new_comment['created_at'].strftime("%Y-%m-%d %H:%M:%S"),
        'is_verified': user['is_verified']
    }

    return jsonify({'status': 'success', 'comment': comment_data})


@app.route('/add_comments', methods=['POST'])
@login_required
async def add_comments():
    data = await request.get_json()
    post_id = data.get('post_id')
    content = data.get('content')

    if not post_id or not content:
        return jsonify({'status': 'error', 'message': 'Invalid input'})

    if len(content) > 175:
        return jsonify({'status': 'error', 'message': 'Comment exceeds 175 characters limit'})

    db = await get_db()
    post = await db.execute('SELECT * FROM post WHERE postid=?', (post_id,))
    post = await post.fetchone()

    if not post:
        return jsonify({'status': 'error', 'message': 'Post not found'})

    user_id = session['userid']
    user = await db.execute('SELECT * FROM user WHERE userid=?', (user_id,))
    user = await user.fetchone()

    last_comment = await db.execute('''
        SELECT * FROM comment WHERE user_id=? AND post_id=?
        ORDER BY created_at DESC LIMIT 1
    ''', (user_id, post_id))
    last_comment = await last_comment.fetchone()

    if last_comment and datetime.utcnow() - last_comment['created_at'] < timedelta(seconds=60):
        return jsonify({'status': 'error', 'message': 'You are commenting too frequently. Please wait before posting another comment.'})

    new_comment = {
        'content': content,
        'user_id': user_id,
        'post_id': post_id,
        'created_at': datetime.utcnow()
    }
    await db.execute('''
        INSERT INTO comment (content, user_id, post_id, created_at)
        VALUES (:content, :user_id, :post_id, :created_at)
    ''', new_comment)
    await db.commit()

    comment_data = {
        'user_avatar': url_for('static', filename='images/' + user['avatar']),
        'user_nickname': user['nickname'],
        'content': content,
        'created_at': new_comment['created_at'].strftime("%Y-%m-%d %H:%M:%S"),
        'is_verified': user['is_verified'],
        'is_banned': user['is_banned']
    }

    return jsonify({'status': 'success', 'comment': comment_data})

@app.route('/set_language/<language>', methods=['POST'])
@login_required
async def set_language(language):
    db = await get_db()
    async with db.execute('UPDATE user SET preferred_language=? WHERE userid=?', (language, session['userid'])):
        await db.commit()
    return jsonify(success=True)

@app.route('/admin')
@login_required
async def admin_dashboard():
    db = await get_db()
    async with db.execute('SELECT * FROM user WHERE userid=?', (session['userid'],)) as cursor:
        user = await cursor.fetchone()

    if not user or not user['is_admin']:
        flash('У вас нет доступа к этой странице.')
        return redirect(url_for('apps'))

    async with db.execute('SELECT * FROM user') as cursor:
        user = await cursor.fetchall()

    async with db.execute('SELECT * FROM post') as cursor:
        post = await cursor.fetchall()

    async with db.execute('SELECT * FROM comment') as cursor:
        comment = await cursor.fetchall()

    language = user['preferred_language'] if user['preferred_language'] else 'en'
    tr = translations.get(language, translations['en'])

    return await render_template('admin_dashboard.html', user=user, post=post, comment=comment, tr=tr)

@app.route('/admin/delete_comment/<int:comment_id>', methods=['POST'])
@login_required
async def delete_comment(comment_id):
    db = await get_db()
    async with db.execute('SELECT * FROM user WHERE userid=?', (session['userid'],)) as cursor:
        admin_user = await cursor.fetchone()

    if not admin_user or not admin_user['is_admin']:
        flash('У вас нет доступа к этой операции.')
        return redirect(url_for('admin_dashboard'))

    try:
        async with db.execute('DELETE FROM comment WHERE id=?', (comment_id,)):
            await db.commit()
        flash(f'Комментарий {comment_id} был удален.', 'success')
    except Exception as e:
        flash(f"Произошла ошибка: {str(e)}", 'error')

    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_post/<string:postid>', methods=['POST'])
@login_required
async def delete_post(postid):
    db = await get_db()
    async with db.execute('SELECT * FROM user WHERE userid=?', (session['userid'],)) as cursor:
        admin_user = await cursor.fetchone()

    if not admin_user or not admin_user['is_admin']:
        flash('У вас нет доступа к этой операции.')
        return redirect(url_for('apps'))

    try:
        await db.execute('DELETE FROM comment WHERE post_id=?', (postid,))
        await db.execute('DELETE FROM post WHERE postid=?', (postid,))
        await db.commit()
        flash(f'Пост {postid} был удален.', 'success')
    except Exception as e:
        flash(f"Произошла ошибка: {str(e)}", 'error')

    return redirect(url_for('apps'))

@app.route('/admin/delete_user/<string:userid>', methods=['POST'])
@login_required
async def delete_user(userid):
    db = await get_db()
    async with db.execute('SELECT * FROM user WHERE userid=?', (session['userid'],)) as cursor:
        admin_user = await cursor.fetchone()

    if not admin_user or not admin_user['is_admin']:
        flash('У вас нет доступа к этой операции.')
        return redirect(url_for('admin_dashboard'))

    try:
        await db.execute('DELETE FROM session WHERE user_id=?', (userid,))
        await db.execute('DELETE FROM user WHERE userid=?', (userid,))
        await db.commit()
        flash(f'User {userid} has been deleted.', 'success')
    except Exception as e:
        flash(f"An error occurred: {str(e)}", 'error')

    return redirect(url_for('admin_dashboard'))

@app.route('/admin/ban_user/<userid>', methods=['POST'])
@login_required
async def ban_user(userid):
    db = await get_db()
    async with db.execute('SELECT * FROM user WHERE userid=?', (session['userid'],)) as cursor:
        admin_user = await cursor.fetchone()

    if not admin_user or not admin_user['is_admin']:
        flash('У вас нет доступа к этой операции.')
        return redirect(url_for('admin_dashboard'))

    try:
        await db.execute('UPDATE user SET is_banned=1 WHERE userid=?', (userid,))
        await db.execute('DELETE FROM comment WHERE user_id=?', (userid,))
        await db.execute('DELETE FROM session WHERE user_id=?', (userid,))
        await db.commit()
        flash(f'User {userid} has been banned successfully.', 'success')
    except Exception as e:
        flash(f"An error occurred: {str(e)}", 'error')

    return redirect(url_for('admin_dashboard'))

@app.route('/search_user', methods=['POST'])
@login_required
async def search_user():
    search_query = (await request.form).get('search_query')
    if not search_query:
        return jsonify([])

    db = await get_db()
    async with db.execute('''SELECT u.*, COUNT(s.subscriber_id) AS subscriber_count
                             FROM user u
                             LEFT JOIN subscriptions s ON u.userid = s.subscribed_to_id
                             WHERE u.nickname LIKE ?
                             GROUP BY u.userid
                             ORDER BY u.is_verified DESC, subscriber_count DESC''',
                          (f'%{search_query}%',)) as cursor:
        popular_user = await cursor.fetchall()

    user_data = [{
        'userid': user['userid'],
        'avatar': url_for('static', filename=f'images/{user["avatar"]}'),
        'nickname': user['nickname'],
        'subscriber_count': user['subscriber_count'],
        'is_verified': user['is_verified']
    } for user in popular_user]

    return jsonify(user_data)

@app.route('/change-avatar', methods=['POST'])
async def change_avatar():
    if 'userid' not in session:
        logging.error("User ID not found in session.")
        return redirect(url_for('login'))

    if 'avatar' not in (await request.files):
        logging.error("No avatar file part in the request.")
        return jsonify({'success': False, 'message': 'No file part in the request'}), 400

    file = (await request.files).get('avatar')
    if file.filename == '':
        logging.error("No selected file.")
        return jsonify({'success': False, 'message': 'No selected file'}), 400

    db = await get_db()
    async with db.execute('SELECT * FROM user WHERE userid=?', (session['userid'],)) as cursor:
        user = await cursor.fetchone()
    
    if not user:
        logging.error("User not found in database.")
        return jsonify({'success': False, 'message': 'User not found'}), 400

    allowed_extensions = {'png', 'jpg', 'jpeg'}
    if user['subscription_status'] == 'turbo_x':
        allowed_extensions.add('gif')

    def allowed_file(filename):
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

    if file and allowed_file(file.filename):
        ext = file.filename.rsplit('.', 1)[1].lower()
        filename = f"{uuid.uuid4().hex}.{ext}"
        file_path = os.path.join(IMAGES_FOLDER, filename)
        
        try:
            await file.save(file_path)
        except Exception as e:
            logging.error(f"Error saving file: {e}")
            return jsonify({'success': False, 'message': 'File saving error'}), 500

        old_avatar = user['avatar']
        await db.execute('UPDATE user SET avatar=? WHERE userid=?', (filename, session['userid']))
        await db.commit()

        session['avatar'] = filename

        protected_avatars = {'user1.png', 'user2.png', 'user3.png', 'user4.png', 'user5.png', 'user6.png', 'user7.png', 'user8.png'}
        
        if old_avatar and old_avatar != 'user3.png' and old_avatar not in protected_avatars:
            old_avatar_path = os.path.join(IMAGES_FOLDER, old_avatar)
            if os.path.exists(old_avatar_path):
                try:
                    os.remove(old_avatar_path)
                except Exception as e:
                    logging.error(f"Error removing old avatar: {e}")
                    return jsonify({'success': False, 'message': 'Error removing old avatar'}), 500

        return jsonify({'success': True}), 200

    return jsonify({'success': False, 'message': 'Invalid file'}), 400

@app.route('/subscribe', methods=['POST'])
@login_required
async def subscribe():
    data = await request.get_json()
    user_id = data.get('user_id')

    if not user_id:
        return jsonify({'status': 'error', 'message': 'User ID not provided'}), 400

    db = await get_db()
    async with db.execute('SELECT * FROM user WHERE userid=?', (session['userid'],)) as cursor:
        user = await cursor.fetchone()

    if not user:
        return jsonify({'status': 'error', 'message': 'User not found'}), 404

    if user_id == session['userid']:
        return jsonify({'status': 'error', 'message': 'Cannot subscribe to yourself'}), 400

    async with db.execute('SELECT * FROM user WHERE userid=?', (user_id,)) as cursor:
        target_user = await cursor.fetchone()

    if not target_user:
        return jsonify({'status': 'error', 'message': 'Target user not found'}), 404

    async with db.execute('SELECT * FROM subscriptions WHERE subscriber_id=? AND subscribed_to_id=?',
                          (session['userid'], user_id)) as cursor:
        subscription = await cursor.fetchone()

    if subscription:
        return jsonify({'status': 'error', 'message': 'Already subscribed to this user'}), 400

    await db.execute('INSERT INTO subscriptions (subscriber_id, subscribed_to_id) VALUES (?, ?)',
                     (session['userid'], user_id))
    await db.execute('INSERT INTO notification (subscriber_id, subscribed_to_id) VALUES (?, ?)',
                     (session['userid'], user_id))
    await db.commit()

    return jsonify({'status': 'success'}), 200

@app.route('/unsubscribe', methods=['POST'])
@login_required
async def unsubscribe():
    data = await request.get_json()
    user_id = data.get('user_id')

    if not user_id:
        return jsonify({'status': 'error', 'message': 'User ID not provided'}), 400

    db = await get_db()
    async with db.execute('SELECT * FROM user WHERE userid=?', (session['userid'],)) as cursor:
        user = await cursor.fetchone()

    if not user:
        return jsonify({'status': 'error', 'message': 'User not found'}), 404

    if user_id == session['userid']:
        return jsonify({'status': 'error', 'message': 'Cannot unsubscribe from yourself'}), 400

    async with db.execute('SELECT * FROM user WHERE userid=?', (user_id,)) as cursor:
        target_user = await cursor.fetchone()

    if not target_user:
        return jsonify({'status': 'error', 'message': 'Target user not found'}), 404

    await db.execute('DELETE FROM subscriptions WHERE subscriber_id=? AND subscribed_to_id=?',
                     (session['userid'], user_id))
    await db.execute('DELETE FROM notification WHERE subscriber_id=? AND subscribed_to_id=?',
                     (session['userid'], user_id))
    await db.commit()

    return jsonify({'status': 'success'}), 200

@app.route('/notifications')
@login_required
async def notifications():
    db = await get_db()
    async with db.execute('SELECT * FROM user WHERE userid=?', (session['userid'],)) as cursor:
        user = await cursor.fetchone()

    async with db.execute('SELECT * FROM notification WHERE subscribed_to_id=? ORDER BY created_at DESC', 
                          (user['userid'],)) as cursor:
        notification = await cursor.fetchall()

    language = user['preferred_language'] if user else 'en'
    tr = translations.get(language, translations['en'])
    return await render_template('notification.html', notification=notification, user=user, tr=tr)

@app.route('/change-nickname', methods=['POST'])
async def change_nickname():
    if 'userid' not in session:
        return jsonify({'success': False, 'message': 'User not logged in.'}), 401

    data = await request.get_json()
    new_nickname = data.get('nickname', '').strip()

    if not new_nickname:
        return jsonify({'success': False, 'message': 'Nickname cannot be empty.'}), 400

    if len(new_nickname) > 12:
        return jsonify({'success': False, 'message': 'Nickname cannot be more than 12 characters long.'}), 400

    normalized_nickname = new_nickname.lower()
    db = await get_db()
    
    async with db.execute('SELECT * FROM user WHERE lower(nickname)=?', (normalized_nickname,)) as cursor:
        existing_user = await cursor.fetchone()

    if existing_user:
        return jsonify({'success': False, 'message': 'Nickname is already taken.'}), 400

    async with db.execute('SELECT * FROM user WHERE userid=?', (session['userid'],)) as cursor:
        user = await cursor.fetchone()

    if not user:
        return jsonify({'success': False, 'message': 'User not found.'}), 404

    try:
        await db.execute('UPDATE user SET nickname=? WHERE userid=?', (new_nickname, session['userid']))
        await db.commit()
        return jsonify({'success': True, 'message': 'Nickname changed successfully.'}), 200
    except Exception as e:
        logging.error(f"Error updating nickname: {e}")
        await db.rollback()
        return jsonify({'success': False, 'message': 'Error updating nickname. Please try again later.'}), 500

@app.route('/verify_user/<userid>', methods=['POST'])
async def verify_user(userid):
    db = await get_db()
    async with db.execute('SELECT * FROM user WHERE userid=?', (userid,)) as cursor:
        user = await cursor.fetchone()

    if user and not user['is_verified']:
        await db.execute('UPDATE user SET is_verified=1 WHERE userid=?', (userid,))
        await db.commit()
        flash(f"User {user['nickname']} has been verified.")
    return redirect(url_for('admin_dashboard'))

@app.route('/change-banner', methods=['POST'])
async def change_banner():
    def allowed_file(filename):
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg'}

    if 'userid' not in session:
        logging.error("User ID not found in session.")
        return redirect(url_for('login'))

    if 'banner' not in (await request.files):
        logging.error("No banner file part in the request.")
        return jsonify({'success': False, 'message': 'No file part in the request'}), 400

    file = (await request.files).get('banner')
    if file.filename == '':
        logging.error("No selected file.")
        return jsonify({'success': False, 'message': 'No selected file'}), 400

    if file and allowed_file(file.filename):
        ext = file.filename.rsplit('.', 1)[1].lower()
        filename = f"{uuid.uuid4().hex}.{ext}"
        file_path = os.path.join(IMAGES_FOLDER, filename)

        try:
            await file.save(file_path)
        except Exception as e:
            logging.error(f"Error saving file: {e}")
            return jsonify({'success': False, 'message': 'File saving error'}), 500

        db = await get_db()
        async with db.execute('SELECT * FROM user WHERE userid=?', (session['userid'],)) as cursor:
            user = await cursor.fetchone()

        if user:
            old_banner = user['banner']
            await db.execute('UPDATE user SET banner=? WHERE userid=?', (filename, session['userid']))
            await db.commit()

            protected_banners = {'default_banner.png'}

            if old_banner and old_banner != 'default_banner.png' and old_banner not in protected_banners:
                old_banner_path = os.path.join(IMAGES_FOLDER, old_banner)
                if os.path.exists(old_banner_path):
                    try:
                        os.remove(old_banner_path)
                    except Exception as e:
                        logging.error(f"Error removing old banner: {e}")
                        return jsonify({'success': False, 'message': 'Error removing old banner'}), 500

            return jsonify({'success': True}), 200
        else:
            logging.error("User not found in database.")
            return jsonify({'success': False, 'message': 'User not found'}), 400

    return jsonify({'success': False, 'message': 'Invalid file'}), 400

@app.route('/confirm_verification', methods=['POST'])
async def confirm_verification():
    db = await get_db()
    async with db.execute('SELECT * FROM user WHERE userid=?', (session['userid'],)) as cursor:
        user = await cursor.fetchone()
    
    if user and user['is_verified'] and not user['verified_date']:
        await db.execute('UPDATE user SET verified_date=? WHERE userid=?', (datetime.utcnow(), session['userid']))
        await db.commit()
        flash(f"Congratulations, {user['nickname']}! You are now officially verified.")
    return redirect(url_for('notification'))

async def update_status(service_name, status):
    db = await get_db()
    async with db.execute('SELECT * FROM status WHERE service_name=?', (service_name,)) as cursor:
        existing_status = await cursor.fetchone()

    if existing_status:
        await db.execute('UPDATE status SET status=?, updated_at=? WHERE service_name=?', (status, datetime.utcnow(), service_name))
    else:
        await db.execute('INSERT INTO status (service_name, status, updated_at) VALUES (?, ?, ?)', (service_name, status, datetime.utcnow()))
    await db.commit()

async def get_status(service_name):
    db = await get_db()
    async with db.execute('SELECT status FROM status WHERE service_name=?', (service_name,)) as cursor:
        status_entry = await cursor.fetchone()
    return status_entry['status'] if status_entry else 'unknown'

async def check_database_status():
    db = await get_db()
    try:
        await db.execute('SELECT 1')
        status = 'operational'
    except Exception as e:
        status = f'error: {e}'
    await update_status('database', status)
    return status

@app.route('/api/status', methods=['GET'])
async def api_status():
    db = await get_db()
    async with db.execute('SELECT * FROM status WHERE service_name="database" ORDER BY updated_at DESC LIMIT 30') as cursor:
        status_history = await cursor.fetchall()

    return jsonify({
        'db_status': [status['status'] for status in status_history]
    })

@app.route('/terms')
async def terms():
    return await render_template('terms.html')

@app.route('/privacy_policy')
async def privacy_policy():
    return await render_template('privacy_policy.html')

@app.route('/api/find_user/<nickname>', methods=['GET'])
async def find_user(nickname):
    db = await get_db()
    async with db.execute('SELECT * FROM user WHERE nickname=?', (nickname,)) as cursor:
        user = await cursor.fetchone()
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    return jsonify({'userid': user['userid'], 'avatar': user['avatar']})

@app.route('/api/account/<userid>', methods=['GET'])
async def get_user_statistics(userid):
    db = await get_db()
    async with db.execute('SELECT * FROM user WHERE userid=?', (userid,)) as cursor:
        user = await cursor.fetchone()

    if not user:
        return jsonify({'error': 'User not found'}), 404

    followers_count = await db.execute('SELECT COUNT(*) FROM subscriptions WHERE subscribed_to_id=?', (userid,))
    following_count = await db.execute('SELECT COUNT(*) FROM subscriptions WHERE subscriber_id=?', (userid,))

    async with db.execute('SELECT * FROM post WHERE user_postid=?', (userid,)) as cursor:
        post = await cursor.fetchall()

    decrypted_post = []
    total_likes = 0
    for post in post:
        try:
            decrypted_post = {
                'postid': post['postid'],
                'title': cipher_suite.decrypt(post['title'].encode()).decode(),
                'description': cipher_suite.decrypt(post['description'].encode()).decode(),
                'image': cipher_suite.decrypt(post['image'].encode()).decode(),
                'likes_count': post['likes_count'],
            }
            total_likes += post['likes_count']
            decrypted_post.append(decrypted_post)
        except Exception as e:
            logging.error(f"Error decrypting post ID {post['postid']}: {e}")

    base_url = 'http://10.6.6.101:5000/static/images/'
    avatar_url = f"{base_url}{user['avatar']}" if user['avatar'] else None

    user_stats = {
        'userid': user['userid'],
        'nickname': user['nickname'],
        'subscriptions_count': following_count,
        'subscribers_count': followers_count,
        'total_likes': total_likes,
        'post': decrypted_post,
        'avatar': avatar_url
    }

    return jsonify(user_stats)

@app.route('/api/top_user', methods=['GET'])
async def get_top_user():
    db = await get_db()
    try:
        async with db.execute('''SELECT u.*, COUNT(s.subscriber_id) AS followers_count
                                 FROM user u
                                 LEFT JOIN subscriptions s ON u.userid = s.subscribed_to_id
                                 GROUP BY u.userid
                                 ORDER BY followers_count DESC
                                 LIMIT 10''') as cursor:
            top_user = await cursor.fetchall()

        user_list = [{'userid': user['userid'], 'nickname': user['nickname'], 'followers_count': user['followers_count']} for user in top_user]

        return jsonify({'top_user': user_list})

    except Exception as e:
        logging.error(f"Error fetching top user: {e}")
        return jsonify({'error': f"An error occurred while fetching top user: {e}"}), 500

@app.route('/api/statistics', methods=['GET'])
async def get_statistics():
    db = await get_db()

    total_user = await db.execute('SELECT COUNT(*) FROM user')
    total_post = await db.execute('SELECT COUNT(*) FROM post')
    total_likes = await db.execute('SELECT SUM(likes_count) FROM post')

    stats = {
        'total_user': total_user,
        'total_post': total_post,
        'total_likes': total_likes or 0
    }

    return jsonify(stats)

@app.route('/api/top_post', methods=['GET'])
async def top_post():
    db = await get_db()
    try:
        async with db.execute('SELECT * FROM post ORDER BY likes_count DESC LIMIT 10') as cursor:
            top_post = await cursor.fetchall()

        post_list = [{'postid': post['postid'], 'title': post['title'], 'likes_count': post['likes_count']} for post in top_post]

        return jsonify({'post': post_list})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/user_activity/<nickname>', methods=['GET'])
async def user_activity(nickname):
    db = await get_db()
    try:
        async with db.execute('SELECT * FROM user WHERE nickname=?', (nickname,)) as cursor:
            user = await cursor.fetchone()

        if not user:
            return jsonify({'error': 'User not found'}), 404

        async with db.execute('SELECT * FROM post WHERE user_postid=? ORDER BY id DESC LIMIT 5', (user['userid'],)) as cursor:
            recent_post = await cursor.fetchall()

        async with db.execute('''SELECT u.* FROM user u
                                 JOIN subscriptions s ON u.userid = s.subscribed_to_id
                                 WHERE s.subscriber_id = ?
                                 ORDER BY s.subscribed_to_id DESC LIMIT 5''', (user['userid'],)) as cursor:
            recent_subscriptions = await cursor.fetchall()

        activity_data = {
            'recent_post': '\n'.join([f"**Post ID**: {post['postid']}\n**Title**: {post['title']}" for post in recent_post]),
            'recent_subscriptions': '\n'.join([f"**User ID**: {sub['userid']}\n**Nickname**: {sub['nickname']}" for sub in recent_subscriptions])
        }

        return jsonify(activity_data)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/')
async def home():
    return await render_template('index.html')

@app.route('/settings')
async def settings():
    if 'userid' in session:
        db = await get_db()
        async with db.execute('SELECT preferred_language FROM user WHERE userid=?', (session['userid'],)) as cursor:
            user = await cursor.fetchone()
        language = user['preferred_language'] if user else 'en'
    else:
        language = 'en'

    user = await db.execute('SELECT * FROM user WHERE userid=?', (session.get('userid'),))
    if not user:
        return redirect(url_for('login'))

    tr = translations.get(language, translations['en'])
    return await render_template('settings.html', user=user, tr=tr)

@app.route('/turbo')
async def turbo():
    if 'userid' not in session:
        flash('You need to log in to access this page.', 'warning')
        return redirect(url_for('login'))

    db = await get_db()
    async with db.execute('SELECT * FROM user WHERE userid=?', (session['userid'],)) as cursor:
        user = await cursor.fetchone()
    return await render_template('turbo.html', user=user)

@app.route('/subscribe/success')
async def subscribe_success():
    if 'userid' not in session:
        flash('You need to log in to complete the subscription.', 'warning')
        return redirect(url_for('login'))

    db = await get_db()
    async with db.execute('SELECT * FROM user WHERE userid=?', (session['userid'],)) as cursor:
        user = await cursor.fetchone()

    if user:
        await db.execute('UPDATE user SET subscription_status="Turbo" WHERE userid=?', (session['userid'],))
        await db.commit()
        flash('Subscription successful! You are now a Turbo user.', 'success')

@app.route('/check_session', methods=['GET'])
async def check_session():
    logged_in = 'userid' in session
    return jsonify({'logged_in': logged_in})

@app.route('/like_post', methods=['POST'])
async def like_post():
    try:
        data = await request.get_json()
        postid = data.get('post_id')

        if not postid:
            return jsonify({'status': 'error', 'message': 'Post ID not provided'}), 400

        db = await get_db()

        async with db.execute('SELECT * FROM post WHERE postid=?', (postid,)) as cursor:
            post = await cursor.fetchone()

        if not post:
            return jsonify({'status': 'error', 'message': 'Post not found'}), 404

        async with db.execute('SELECT * FROM user WHERE userid=?', (session['userid'],)) as cursor:
            user = await cursor.fetchone()

        if not user:
            return jsonify({'status': 'error', 'message': 'User not found'}), 404

        async with db.execute('SELECT * FROM user_likes WHERE user_id=? AND post_id=?', (user['userid'], postid)) as cursor:
            liked_post = await cursor.fetchone()

        if liked_post:
            await db.execute('DELETE FROM user_likes WHERE user_id=? AND post_id=?', (user['userid'], postid))
            post_likes_count = post['likes_count'] - 1
            is_liked = False
        else:
            await db.execute('INSERT INTO user_likes (user_id, post_id) VALUES (?, ?)', (user['userid'], postid))
            post_likes_count = post['likes_count'] + 1
            is_liked = True

        await db.execute('UPDATE post SET likes_count=? WHERE postid=?', (post_likes_count, postid))
        await db.commit()

        return jsonify({'status': 'success', 'likes_count': post_likes_count, 'is_liked': is_liked}), 200

    except Exception as e:
        logging.error(f"Error in like_post: {e}")
        return jsonify({'status': 'error', 'message': 'Internal Server Error'}), 500

@app.route('/check_like', methods=['GET'])
async def check_like():
    postid = request.args.get('post_id')
    
    if not postid:
        return jsonify({'status': 'error', 'message': 'Post ID not provided'}), 400

    db = await get_db()

    async with db.execute('SELECT * FROM post WHERE postid=?', (postid,)) as cursor:
        post = await cursor.fetchone()

    if not post:
        return jsonify({'status': 'error', 'message': 'Post not found'}), 404

    if 'userid' not in session:
        return jsonify({'status': 'error', 'message': 'User not logged in'}), 401

    async with db.execute('SELECT * FROM user WHERE userid=?', (session['userid'],)) as cursor:
        user = await cursor.fetchone()

    if not user:
        return jsonify({'status': 'error', 'message': 'User not found'}), 404

    async with db.execute('SELECT * FROM user_likes WHERE user_id=? AND post_id=?', (user['userid'], postid)) as cursor:
        is_liked = await cursor.fetchone() is not None

    return jsonify({'status': 'success', 'is_liked': is_liked}), 200

@app.route('/save_post', methods=['POST'])
async def save_post():
    data = await request.get_json()
    postid = data.get('post_id')

    if not postid:
        return jsonify({'status': 'error', 'message': 'Post ID not provided'})

    db = await get_db()

    async with db.execute('SELECT * FROM post WHERE postid=?', (postid,)) as cursor:
        post = await cursor.fetchone()

    if not post:
        return jsonify({'status': 'error', 'message': 'Post not found'})

    user_id = (await db.execute('SELECT id FROM user WHERE userid=?', (session['userid'],))).fetchone()['id']

    return jsonify({'status': 'success', 'message': 'Save functionality not implemented yet'})

# Асинхронный просмотр поста
@app.route('/post/<string:postid>', methods=['GET'])
async def view_post(postid):
    db = await get_db()

    async with db.execute('SELECT * FROM post WHERE postid=?', (postid,)) as cursor:
        post = await cursor.fetchone()

    decrypted_title = cipher_suite.decrypt(post['title'].encode()).decode()
    decrypted_description = cipher_suite.decrypt(post['description'].encode()).decode()
    decrypted_image_filename = cipher_suite.decrypt(post['image'].encode()).decode()

    return await render_template('view_post.html', 
                                 title=decrypted_title, 
                                 description=decrypted_description, 
                                 image_url=url_for('static', filename=f'uploads/{decrypted_image_filename}'))

# Асинхронное создание поста
@app.route('/create', methods=['GET', 'POST'])
async def create():
    db = await get_db()

    async with db.execute('SELECT * FROM user WHERE userid=?', (session['userid'],)) as cursor:
        user = await cursor.fetchone()

    language = user['preferred_language'] if user else 'en'
    tr = translations.get(language, translations['en'])

    if request.method == 'POST':
        title = (await request.form)['title']
        description = (await request.form)['description']
        image = (await request.files).get('image')

        if not title or not description or not image:
            flash('All fields are required.', 'error')
            return redirect(url_for('create'))

        random_filename = f"{uuid.uuid4().hex}{os.path.splitext(image.filename)[1]}"
        image_filename = secure_filename(random_filename)

        if not os.path.exists('static/uploads'):
            os.makedirs('static/uploads')

        image_path = os.path.join('static/uploads', image_filename)
        await image.save(image_path)

        resized_image = Image.open(image_path)
        resized_image = resized_image.resize((512, 512))

        _, file_extension = os.path.splitext(image_filename)
        valid_extensions = {'.jpg': 'JPEG', '.jpeg': 'JPEG', '.png': 'PNG'}
        if file_extension.lower() not in valid_extensions:
            flash('Unsupported image format.', 'error')
            return redirect(url_for('create'))

        image_format = valid_extensions[file_extension.lower()]

        if resized_image.mode == 'RGBA' and image_format == 'JPEG':
            resized_image = resized_image.convert('RGB')

        resized_image.save(image_path, format=image_format)

        postid = generate_unique_postid()
        encrypted_title = cipher_suite.encrypt(title.encode()).decode()
        encrypted_description = cipher_suite.encrypt(description.encode()).decode()
        encrypted_image_filename = cipher_suite.encrypt(image_filename.encode()).decode()

        await db.execute('INSERT INTO post (title, description, image, user_postid, postid) VALUES (?, ?, ?, ?, ?)',
                         (encrypted_title, encrypted_description, encrypted_image_filename, user['userid'], postid))
        await db.commit()

        flash(f"Post created successfully with ID {postid}.", 'success')
        return redirect(url_for('apps'))

    return await render_template('create.html', tr=tr)

@app.route('/.well-known/pki-validation/<filename>')
async def serve_validation_file(filename):
    return await send_from_directory('static/.well-known/pki-validation', filename)

@app.route('/register', methods=['GET', 'POST'])
async def register():
    if 'userid' in session:
        return redirect(url_for('apps', _external=True, message="Вы уже зарегистрированы и вошли в систему.", message_type='info'))

    if request.method == 'POST':
        form = await request.form
        recaptcha_token = form.get('g-recaptcha-response')
        if not await verify_recaptcha(recaptcha_token):
            return redirect(url_for('register', _external=True, message="Проверка reCAPTCHA не пройдена.", message_type='register_error'))

        nickname = form['nickname']
        password = form['password']
        terms_accepted = form.get('terms')
        honeypot = form.get('honeypot')

        if honeypot:
            return redirect(url_for('register', _external=True, message="Обнаружена недействительная попытка регистрации.", message_type='register_error'))

        if not terms_accepted:
            return redirect(url_for('register', _external=True, message="Вы должны согласиться с Условиями использования и Политикой конфиденциальности.", message_type='register_error'))

        if len(password) < 8 or not any(c.isalpha() for c in password) or not any(c.isdigit() for c in password):
            return redirect(url_for('register', _external=True, message="Пароль должен содержать минимум 8 символов, включая буквы и цифры.", message_type='register_error'))

        if len(nickname) < 4 or sum(c.isalpha() for c in nickname) < 4 or nickname.isdigit():
            return redirect(url_for('register', _external=True, message="Никнейм должен быть длиной минимум 4 символа, содержать минимум 4 буквы и не может состоять только из цифр.", message_type='register_error'))

        db = await get_db()
        async with db.execute('SELECT * FROM user WHERE nickname=?', (nickname,)) as cursor:
            existing_user = await cursor.fetchone()
            if existing_user:
                return redirect(url_for('register', _external=True, message="Никнейм уже занят.", message_type='register_error'))

        avatars = ['user1.png', 'user2.png', 'user3.png', 'user4.png', 'user5.png', 'user6.png', 'user7.png', 'user8.png']
        avatar = random.choice(avatars)
        user_id = str(uuid.uuid4())

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        await db.execute('INSERT INTO user (userid, nickname, password, avatar) VALUES (?, ?, ?, ?)',
                         (user_id, nickname, hashed_password, avatar))
        await db.commit()

        session_id = str(uuid.uuid4())
        expires_at = datetime.utcnow() + timedelta(days=31)

        await db.execute('INSERT INTO session (session_id, user_id, expires_at) VALUES (?, ?, ?)',
                         (session_id, user_id, expires_at))
        await db.commit()

        session['session_id'] = session_id
        session['userid'] = user_id
        session['avatar'] = avatar

        return redirect(url_for('apps', _external=True, message="Регистрация прошла успешно.", message_type='success'))

    return await render_template('register.html', message=request.args.get('message'), message_type=request.args.get('message_type'))

@app.route('/login', methods=['GET', 'POST'])
async def login():
    if 'userid' in session:
        return redirect(url_for('apps', message="Вы уже вошли в систему.", message_type='info'))

    db = await get_db()
    messages = {}
    failed_attempts = None  

    if request.method == 'POST':
        form = await request.form
        nickname = form.get('nickname')
        password = form.get('password')

        if not nickname or not password:
            messages['error'] = "Please provide both nickname and password."
            return await render_template('login.html', messages=messages)

        async with db.execute('SELECT * FROM failed_login_attempt WHERE ip_address=?', (request.remote_addr,)) as cursor:
            failed_attempts = await cursor.fetchone()

        if failed_attempts and failed_attempts['attempt_count'] >= CAPTCHA_REQUIRED_ATTEMPTS:
            recaptcha_token = form.get('g-recaptcha-response')
            if not await verify_recaptcha(recaptcha_token):
                messages['error'] = "reCAPTCHA verification failed. Please try again."
                return await render_template('login.html', messages=messages)

        async with db.execute('SELECT * FROM user WHERE nickname=?', (nickname,)) as cursor:
            user = await cursor.fetchone()
        
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            if user['is_banned']:
                messages['error'] = 'Your account has been banned.'
                return await render_template('login.html', messages=messages)

            if failed_attempts:
                await db.execute('DELETE FROM failed_login_attempt WHERE ip_address=?', (request.remote_addr,))
                await db.commit()

            session_id = str(uuid.uuid4())
            expires_at = datetime.utcnow() + timedelta(days=1)

            await db.execute('INSERT INTO session (session_id, user_id, expires_at) VALUES (?, ?, ?)',
                             (session_id, user['userid'], expires_at))
            await db.commit()

            session.permanent = True
            session['session_id'] = session_id
            session['userid'] = user['userid']
            session['avatar'] = user['avatar']

            messages['success'] = "Login successful."
            return redirect(url_for('apps'))  # Remove 'await' here
        else:
            messages['error'] = "Invalid nickname or password. Please try again."

            if failed_attempts:
                await db.execute('UPDATE failed_login_attempt SET attempt_count=?, last_attempt_time=? WHERE ip_address=?',
                                 (failed_attempts['attempt_count'] + 1, datetime.utcnow(), request.remote_addr))
            else:
                await db.execute('INSERT INTO failed_login_attempt (ip_address, attempt_count, last_attempt_time) VALUES (?, ?, ?)',
                                 (request.remote_addr, 1, datetime.utcnow()))
            
            await db.commit()

            if failed_attempts and failed_attempts['attempt_count'] >= MAX_FAILED_ATTEMPTS:
                messages['error'] = "Too many failed login attempts. Please try again later or solve reCAPTCHA."

    return await render_template('login.html', messages=messages)

@app.before_request
async def load_logged_in_user():
    db = await get_db()
    session_id = session.get('session_id')

    if session_id:
        async with db.execute('SELECT * FROM session WHERE session_id=?', (session_id,)) as cursor:
            session_record = await cursor.fetchone()

        if session_record:
            user_session = dict(session_record)

            expires_at_str = user_session.get('expires_at')
            if isinstance(expires_at_str, str):
                try:
                    user_session['expires_at'] = datetime.fromisoformat(expires_at_str)
                except ValueError:
                    user_session['expires_at'] = None

            if user_session['expires_at'] and user_session['expires_at'] > datetime.utcnow():
                async with db.execute('SELECT * FROM user WHERE userid=?', (user_session['user_id'],)) as cursor:
                    g.current_user = await cursor.fetchone()

                new_expiry_time = datetime.utcnow() + timedelta(days=1)
                await db.execute('UPDATE session SET expires_at=? WHERE session_id=?', (new_expiry_time, session_id))
                await db.commit()

                session.permanent = True
                session.modified = True
            else:
                g.current_user = None
                if user_session:
                    await db.execute('DELETE FROM session WHERE session_id=?', (session_id,))
                    await db.commit()
                session.clear()
    else:
        g.current_user = None

async def update_session_expiry(session_id, expiry_time):
    try:
        db = await get_db()
        await db.execute('UPDATE session SET expires_at=? WHERE session_id=?', (expiry_time, session_id))
        await db.commit()
    except Exception as e:
        await db.rollback()
        logging.error(f"Error updating session expiry: {e}")

async def clear_expired_session():
    now = datetime.utcnow()
    db = await get_db()
    await db.execute('DELETE FROM session WHERE expires_at < ?', (now,))
    await db.commit()

scheduler = BackgroundScheduler()
scheduler.add_job(func=clear_expired_session, trigger="interval", hours=1)
scheduler.start()

atexit.register(lambda: scheduler.shutdown())

@app.route('/logout')
async def logout():
    session.clear()
    flash("You have been logged out.", 'info')
    return redirect(url_for('login'))

class IncrementalTFIDFVectorizer(TfidfVectorizer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.tfidf_matrix = None

    def fit_transform_incremental(self, new_docs):
        if self.tfidf_matrix is None:
            self.tfidf_matrix = super().fit_transform(new_docs)
        else:
            new_tfidf_matrix = super().transform(new_docs)
            self.tfidf_matrix = np.vstack([self.tfidf_matrix, new_tfidf_matrix])
        return self.tfidf_matrix

    def fit_incremental(self, new_docs):
        if self.tfidf_matrix is None:
            self.tfidf_matrix = super().fit_transform(new_docs)
        else:
            super().fit(new_docs)

def get_content_based_recommendations(user, post, vectorizer, svd):
    if user is None:
        raise ValueError("User cannot be None")

    post_descriptions = [post['description'] for post in post]
    tfidf_matrix = vectorizer.transform(post_descriptions)
    reduced_matrix = svd.transform(tfidf_matrix)

    cosine_sim = linear_kernel(reduced_matrix, reduced_matrix)
    indices = {post['postid']: i for i, post in enumerate(post)}

    liked_post_indices = [indices[post['postid']] for post in user['liked_posts'] if post['postid'] in indices]
    if not liked_post_indices:
        return []

    mean_similarities = np.mean(cosine_sim[liked_post_indices], axis=0)
    recommended_indices = np.argsort(mean_similarities)[::-1]

    recommended_post = [post[i] for i in recommended_indices if post[i]['user_postid'] != user['userid']]

    return recommended_post

def get_collaborative_filtering_recommendations(current_user, users, post):
    user_post_matrix = np.zeros((len(users), len(post)))

    for i, u in enumerate(users):
        if 'liked_post' in u: 
            for post in u['liked_post']:
                if post in post:
                    user_post_matrix[i, post.index(post)] = 1

    if user_post_matrix.shape[1] == 0 or np.all(user_post_matrix == 0):
        logging.warning("No valid interactions found for collaborative filtering.")
        return []

    user_similarities = linear_kernel(user_post_matrix, user_post_matrix)
    
    user_idx = users.index(current_user)
    
    similar_user_indices = np.argsort(user_similarities[user_idx])[::-1][1:]

    recommended_post = []
    seen_post_ids = set([post['postid'] for post in current_user.get('liked_post', [])])

    for idx in similar_user_indices:
        similar_user = users[idx]
        if 'liked_post' in similar_user:  
            for post in similar_user['liked_post']:
                if post['postid'] not in seen_post_ids and post['user_postid'] != current_user['userid']:
                    recommended_post.append(post)
                    seen_post_ids.add(post['postid'])

    return recommended_post


def get_hybrid_recommendations(user, users, post, vectorizer, svd, nmf_model):
    post_descriptions = [post['description'] for post in post if post['description'].strip()]

    try:
        content_based_post = get_content_based_recommendations(user, post, vectorizer, svd)
    except Exception:
        content_based_post = []

    collaborative_post = get_collaborative_filtering_recommendations(user, user, post)
    popular_post = get_popular_post(post)

    all_recommended_post = content_based_post + collaborative_post + popular_post
    unique_recommended_post = list({post['postid']: post for post in all_recommended_post}.values())

    return unique_recommended_post

async def get_recommended_post(user, users, post, prioritize_postid=None):
    vectorizer, svd, nmf_model = await update_models()

    recommended_post = get_hybrid_recommendations(user, user, post, vectorizer, svd, nmf_model)
    decrypted_recommended_post = []
    prioritized_post = None

    for post in recommended_post:
        try:
            decrypted_post = {
                'postid': post['postid'],
                'title': cipher_suite.decrypt(post['title'].encode()).decode(),
                'description': cipher_suite.decrypt(post['description'].encode()).decode(),
                'image': cipher_suite.decrypt(post['image'].encode()).decode(),
                'user': {
                    'userid': post['user_postid'],
                    'avatar': post['user']['avatar'],
                    'nickname': post['user']['nickname'],
                    'is_verified': post['user']['is_verified']
                },
                'likes_count': post['likes_count'],
                'is_self': user['userid'] == post['user_postid'],
                'is_subscribed': post['user_postid'] in [s['userid'] for s in user['subscriptions']]
            }
            if prioritize_postid and post['postid'] == prioritize_postid:
                prioritized_post = decrypted_post
            else:
                decrypted_recommended_post.append(decrypted_post)
        except Exception as e:
            logging.error(f"Error decrypting post ID {post['postid']}: {e}")

    if prioritized_post:
        decrypted_recommended_post.insert(0, prioritized_post)

    return decrypted_recommended_post

async def update_models():
    db = await get_db()
    async with db.execute('SELECT description FROM post') as cursor:
        posts = await cursor.fetchall()

    post_descriptions = [post['description'] for post in posts if post['description'].strip()]
    vectorizer = TfidfVectorizer(stop_words='english')

    if not post_descriptions:
        dummy_data = ["dummy data to fit vectorizer"]
        vectorizer.fit(dummy_data)

        logging.warning("No valid post descriptions to process. Returning default models.")
        svd = TruncatedSVD(n_components=1)
        nmf_model = NMF(n_components=1)

        return vectorizer, svd, nmf_model

    tfidf_matrix = vectorizer.fit_transform(post_descriptions)
    n_components = min(100, tfidf_matrix.shape[1])
    svd = TruncatedSVD(n_components=n_components)
    svd.fit(tfidf_matrix)

    async with db.execute('SELECT * FROM user') as cursor:
        users = await cursor.fetchall()

    user_post_matrix = np.zeros((len(users), len(posts)))
    for i, u in enumerate(users):
        async with db.execute('SELECT * FROM user_likes WHERE user_id=?', (u['userid'],)) as cursor:
            liked_posts = await cursor.fetchall()
        for liked_post in liked_posts:
            for post in posts:
                if post['postid'] == liked_post['post_id']:
                    user_post_matrix[i, posts.index(post)] = 1

    nmf_model = NMF(n_components=50)
    nmf_model.fit(user_post_matrix)

    return vectorizer, svd, nmf_model

@app.route('/app')
async def apps():
    if 'session_id' not in session:
        logging.error("ID сессии не найден.")
        return redirect(url_for('login'))

    db = await get_db()
    async with db.execute('SELECT * FROM session WHERE session_id=?', (session['session_id'],)) as cursor:
        session_record = await cursor.fetchone()

    if session_record:
        session_record = dict(session_record)
        if isinstance(session_record['expires_at'], str):
            session_record['expires_at'] = datetime.fromisoformat(session_record['expires_at'])

        if session_record['expires_at'] < datetime.utcnow():
            logging.error("Недействительная или истекшая сессия.")
            session.pop('session_id', None)
            return redirect(url_for('login'))
    else:
        logging.error("Session ID not found.")
        session.pop('session_id', None)
        return redirect(url_for('login'))

    async with db.execute('SELECT * FROM user WHERE userid=?', (session_record['user_id'],)) as cursor:
        user = await cursor.fetchone()
    
    if user is None:
        logging.error("Пользователь не найден.")
        return redirect(url_for('login'))

    user = dict(user)

    language = user['preferred_language'] if 'preferred_language' in user and user['preferred_language'] else 'en'
    tr = translations.get(language, translations['en'])

    cached_response = await get_cached_data(session['session_id'], db)
    if cached_response:
        return cached_response

    async with db.execute(''' 
        SELECT u.*, COUNT(s.subscriber_id) as subscriber_count 
        FROM user u
        LEFT JOIN subscriptions s ON u.userid = s.subscribed_to_id
        GROUP BY u.userid
        ORDER BY subscriber_count DESC LIMIT 10
    ''') as cursor:
        popular_users = await cursor.fetchall()
        popular_users = [dict(user) for user in popular_users]
        logging.debug(f"Popular users: {popular_users}")

    async with db.execute('SELECT * FROM post') as cursor:
        posts = await cursor.fetchall()
        posts = [dict(post) for post in posts]
    
    if not popular_users:
        popular_users = [{
            'userid': 'none',
            'avatar': 'default.png',
            'nickname': 'No Users',
            'subscriber_count': 0,
            'is_subscribed': False,
            'is_verified': False
        }]

    comment_data = {}
    for post in posts:
        async with db.execute('''SELECT c.id, c.content, c.created_at, u.nickname as user_nickname, u.avatar as user_avatar, u.is_verified 
                                 FROM comment c
                                 JOIN user u ON c.user_id = u.userid
                                 WHERE c.post_id=?''', (post['postid'],)) as cursor:
            comments = await cursor.fetchall()
            comments = [dict(comment) for comment in comments]

        comment_data[post['postid']] = [{
            'id': comment['id'],
            'content': comment['content'],
            'created_at': comment['created_at'],
            'user_nickname': comment.get('user_nickname'),
            'user_avatar': comment.get('user_avatar'),
            'is_verified': comment.get('is_verified')
        } for comment in comments]

    post_id_for_sidebar = posts[0]['postid'] if posts else None

    recommended_post = get_recommended_post(user=user, users=popular_users, post=post_id_for_sidebar)

    response = await render_template('main.html',
                                     user=user,
                                     post=recommended_post,
                                     popular_users=popular_users,
                                     comment_data=comment_data,
                                     post_id=post_id_for_sidebar,
                                     tr=tr)

    await cache_data(session['session_id'], response, db)

    return response

def get_popular_post(posts, top_n=10):
    """
    Get the most popular post based on the number of likes.
    
    :param posts: List of post dictionaries
    :param top_n: Number of top popular post to return
    :return: List of popular post dictionaries
    """
    # Sort posts by likes_count in descending order
    sorted_posts = sorted(posts, key=lambda x: x.get('likes_count', 0), reverse=True)
    
    popular_posts = sorted_posts[:top_n]
    
    return popular_posts

@app.route('/deleted_post/<int:post_id>', methods=['POST'])
async def deleted_post(post_id):
    db = await get_db()
    async with db.execute('SELECT * FROM post WHERE id=?', (post_id,)) as cursor:
        post = await cursor.fetchone()

    if post['user_id'] != session['userid']:
        flash('У вас нет прав на удаление этого поста', 'error')
        return redirect(url_for('index'))

    try:
        await db.execute('DELETE FROM post WHERE id=?', (post_id,))
        await db.commit()
        flash('Пост успешно удален', 'success')
    except Exception as e:
        await db.rollback()
        flash('Ошибка при удалении поста', 'error')

    return redirect(url_for('index'))

@app.route('/profile/<userid>')
async def profile(userid):
    db = await get_db()

    if 'userid' not in session:
        logging.error("User ID not found in session.")
        return redirect(url_for('login'))

    async with db.execute('SELECT * FROM user WHERE userid=?', (userid,)) as cursor:
        user = await cursor.fetchone()

    if not user:
        return redirect(url_for('apps'))

    current_user_id = session.get('userid')
    async with db.execute('SELECT * FROM user WHERE userid=?', (current_user_id,)) as cursor:
        current_user = await cursor.fetchone()

    is_subscribed = bool(await db.execute('SELECT * FROM subscriptions WHERE subscriber_id=? AND subscribed_to_id=?', 
                                          (current_user_id, userid)))

    language = current_user['preferred_language'] if current_user and current_user['preferred_language'] else user['preferred_language']
    tr = translations.get(language, translations['en'])

    followers_count = await db.execute('SELECT COUNT(*) FROM subscriptions WHERE subscribed_to_id=?', (userid,))
    following_count = await db.execute('SELECT COUNT(*) FROM subscriptions WHERE subscriber_id=?', (userid,))

    async with db.execute('SELECT * FROM post WHERE user_postid=? ORDER BY created_at DESC', (userid,)) as cursor:
        post = await cursor.fetchall()

    decrypted_post = []
    total_likes = 0  

    for post in post:
        try:
            decrypted_post = {
                'postid': post['postid'],
                'title': cipher_suite.decrypt(post['title'].encode()).decode(),
                'description': cipher_suite.decrypt(post['description'].encode()).decode(),
                'image': cipher_suite.decrypt(post['image'].encode()).decode(),
                'likes_count': post['likes_count'],
            }
            total_likes += post['likes_count']  
            decrypted_post.append(decrypted_post)
        except Exception as e:
            logging.error(f"Error decrypting post ID {post['postid']}: {e}")

    return await render_template('profile.html', user=user, followers_count=followers_count,
                                 following_count=following_count, post=decrypted_post,
                                 total_likes=total_likes, tr=tr, is_subscribed=is_subscribed)

async def get_recommended_post(user, users, post):
    vectorizer, svd, nmf_model = await update_models()
    recommended_post = get_hybrid_recommendations(user, user, post, vectorizer, svd, nmf_model)

    decrypted_recommended_post = []
    for post in recommended_post:
        try:
            decrypted_post = {
                'postid': post['postid'],
                'title': cipher_suite.decrypt(post['title'].encode()).decode(),
                'description': cipher_suite.decrypt(post['description'].encode()).decode(),
                'image': cipher_suite.decrypt(post['image'].encode()).decode(),
                'likes_count': post['likes_count']
            }
            decrypted_recommended_post.append(decrypted_post)
        except Exception as e:
            logging.error(f"Error decrypting post ID {post['postid']}: {e}")

    return decrypted_recommended_post

async def update_models():
    db = await get_db()
    async with db.execute('SELECT description FROM post') as cursor:
        post = await cursor.fetchall()

    post_descriptions = [post['description'] for post in post if post['description'].strip()]
    vectorizer = TfidfVectorizer(stop_words='english')

    if not post_descriptions:
        dummy_data = ["dummy data to fit vectorizer"]
        vectorizer.fit(dummy_data)

        logging.warning("No valid post descriptions to process. Returning default models.")
        svd = TruncatedSVD(n_components=1)
        nmf_model = NMF(n_components=1)

        return vectorizer, svd, nmf_model

    tfidf_matrix = vectorizer.fit_transform(post_descriptions)
    n_components = min(100, tfidf_matrix.shape[1])
    svd = TruncatedSVD(n_components=n_components)
    svd.fit(tfidf_matrix)

    async with db.execute('SELECT * FROM user') as cursor:
        user = await cursor.fetchall()

    user_post_matrix = np.zeros((len(user), len(post)))
    for i, u in enumerate(user):
        async with db.execute('SELECT * FROM user_likes WHERE user_id=?', (u['userid'],)) as cursor:
            liked_posts = await cursor.fetchall()
        for post in liked_posts:
            if post in post:
                user_post_matrix[i, post.index(post)] = 1

    nmf_model = NMF(n_components=50)
    nmf_model.fit(user_post_matrix)

    return vectorizer, svd, nmf_model

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
