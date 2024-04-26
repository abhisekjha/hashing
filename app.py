import sqlite3
from flask import Flask, render_template, request, url_for, flash, redirect, send_from_directory
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import os
from werkzeug.utils import secure_filename
import hashlib
import time
from flask import send_file
import io
from datetime import datetime
from flask import send_file

app = Flask(__name__, static_url_path='', static_folder='static')

app.config['SECRET_KEY'] = os.urandom(24)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

def encrypt_file(key, filename):
    with open(filename, 'rb') as f:
        data = f.read()
    encrypted = key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

def decrypt_file(key, encrypted_data):
    decrypted = key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

class User(UserMixin):
    def __init__(self, id, username, email):
        self.id = id
        self.username = username
        self.email = email

# Allowed hashing algorithms
ALLOWED_ALGORITHMS = {'sha256', 'md5'}

# Function to hash a file securely
def hash_file(file_path, algorithm='sha256'):
    if algorithm.lower() not in ALLOWED_ALGORITHMS:
        raise ValueError("Invalid hashing algorithm")

    hasher = hashlib.new(algorithm.lower())
    with open(file_path, 'rb') as f:
        while True:
            data = f.read(65536)  # Read in 64k chunks
            if not data:
                break
            hasher.update(data)

    return hasher.hexdigest()



@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    if user:
        return User(id=user['id'], username=user['username'], email=user['email'])
    return None

# Define allowed file extensions and maximum file size
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
MAX_FILE_SIZE = 1 * 1024 * 1024  # 1 MB limit
MAX_FILES_COUNT = 8

app.config['UPLOAD_FOLDER'] = 'uploads/'

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

        conn = get_db_connection()
        user_count = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
        if user_count >= 100:
            flash('Registration limit reached. No additional users can be registered.')
            conn.close()
            return render_template('register.html')

        try:
            conn.execute('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)', (username, email, password_hash))
            conn.commit()
        except sqlite3.IntegrityError:
            flash('Username or email already exists.')
            conn.close()
            return render_template('register.html')
        finally:
            if conn:
                conn.close()

        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if user and bcrypt.check_password_hash(user['password_hash'], password):
            user_obj = User(id=user['id'], username=user['username'], email=user['email'])
            login_user(user_obj)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')

    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/generate_key')
@login_required
def generate_key():
    conn = get_db_connection()
    key_count = conn.execute('SELECT COUNT(*) FROM keys WHERE user_id = ?', (current_user.id,)).fetchone()[0]
    if key_count >= 20:
        flash('You have reached the limit of 20 cryptographic keys.')
        return redirect(url_for('dashboard'))

    # Generate a new key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    private_key = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Store the key in the database
    conn.execute('INSERT INTO keys (user_id, key_data) VALUES (?, ?)', (current_user.id, private_key.decode('utf-8')))
    conn.commit()
    conn.close()

    flash('A new cryptographic key has been generated.')
    return render_template('display_keys.html', private_key=private_key.decode('utf-8'), public_key=public_key.decode('utf-8'))


@app.route('/upload_file', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            if file.content_length > MAX_FILE_SIZE:
                flash('File size exceeds maximum limit.')
                return redirect(request.url)
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            upload_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
           
            # Hash the file
            md5_hash = hash_file('md5', file_path)
            sha256_hash = hash_file('sha256', file_path)

            # Encrypt the file
            conn = get_db_connection()
            key = conn.execute('SELECT * FROM keys WHERE user_id = ?', (current_user.id,)).fetchone()
            if not key:
                flash('No cryptographic key found. Please generate a key.')
                return redirect(url_for('dashboard'))
            private_key = serialization.load_pem_private_key(key['key_data'].encode('utf-8'), password=None)
            encrypted_data = encrypt_file(private_key, file_path)
            encrypted_file_path = os.path.join(app.config['UPLOAD_FOLDER'], f'encrypted_{filename}')
            with open(encrypted_file_path, 'wb') as f:
                f.write(encrypted_data)

            # Store file information in the database
            conn.execute('INSERT INTO files (user_id, filename, md5_hash, sha256_hash, encrypted_file_path) VALUES (?, ?, ?, ?, ?)',
                            (current_user.id, filename, md5_hash, sha256_hash, encrypted_file_path))
            conn.commit()
            conn.close()


            flash('File successfully uploaded.')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid file type.')
            return redirect(request.url)
    # For GET request
    return render_template('upload_file.html')

# @app.route('/view_files')
# @login_required
# def view_files():
#     conn = get_db_connection()
#     user_files = conn.execute("SELECT * FROM files WHERE user_id = ?", (current_user.id,)).fetchall()
#     conn.close()

#     for file in user_files:
#         print(file['filename']) 

#     if not user_files:
#         print("No files found for user:", current_user.id)
#         flash('No files found.')
#     return render_template('view_files.html', files=user_files)
@app.route('/view_files')
@login_required
def view_files():
    conn = get_db_connection()
    user_files = conn.execute("SELECT id, filename, upload_date FROM files WHERE user_id = ?", (current_user.id,)).fetchall()
    conn.close()

    if not user_files:
        flash('No files found.')
    return render_template('view_files.html', files=user_files)

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_new_password = request.form['confirm_new_password']

        # Verify current password
        user = get_db_connection().execute('SELECT * FROM users WHERE id = ?', (current_user.id,)).fetchone()
        if not bcrypt.check_password_hash(user['password_hash'], current_password):
            flash('Current password is incorrect.')
            return render_template('change_password.html')
        
        # Check new password confirmation
        if new_password != confirm_new_password:
            flash('New passwords do not match.')
            return render_template('change_password.html')
        
        # Update password
        new_password_hash = bcrypt.generate_password_hash(new_password)
        conn = get_db_connection()
        conn.execute('UPDATE users SET password_hash = ? WHERE id = ?', (new_password_hash, current_user.id))
        conn.commit()
        conn.close()
        flash('Your password has been updated.')
        return redirect(url_for('dashboard'))

    return render_template('change_password.html')

@app.route('/delete_account', methods=['GET', 'POST'])
@login_required
def delete_account():
    if request.method == 'POST':
        conn = get_db_connection()
        conn.execute('DELETE FROM users WHERE id = ?', (current_user.id,))
        conn.commit()
        conn.close()
        logout_user()
        flash('Your account has been deleted.')
        return redirect(url_for('index'))
    else:
        return render_template('confirm_delete_account.html')

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('index'))

@app.route('/view_keys')
@login_required
def view_keys():
    conn = get_db_connection()
    user_keys = conn.execute('SELECT * FROM keys WHERE user_id = ?', (current_user.id,)).fetchall()
    conn.close()
    return render_template('view_keys.html', keys=user_keys)


@app.route('/download_file/<filename>')
@login_required
def download_file(filename):
    """Send a file to user for download."""
    directory = os.path.join(app.config['UPLOAD_FOLDER'])
    return send_from_directory(directory, filename, as_attachment=True)

@app.route('/delete_file/<filename>')
@login_required
def delete_file(filename):
    """Delete a file from the filesystem."""
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(file_path):
        os.remove(file_path)
        flash('File has been deleted.')
    else:
        flash('File not found.')
    return redirect(url_for('upload_file'))


@app.route('/files/<filename>')
@login_required
def file_download(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/some-process')
def some_process():
    start_time = time.time()
    # Process logic here
    elapsed_time = time.time() - start_time
    flash(f'Operation completed in {elapsed_time:.2f} seconds.')
    return render_template('results.html', time_taken=f'{elapsed_time:.2f} seconds')

@app.route('/download_encrypted_file/<filename>')
@login_required
def download_encrypted_file(filename):
    conn = get_db_connection()
    file = conn.execute('SELECT * FROM files WHERE filename = ?', (filename,)).fetchone()
    conn.close()
    if not file:
        flash('File not found.')
        return redirect(url_for('view_files'))

    return send_file(file['encrypted_file_path'], as_attachment=True)

@app.route('/delete_encrypted_file/<filename>')
@login_required
def delete_encrypted_file(filename):
    conn = get_db_connection()
    file = conn.execute('SELECT * FROM files WHERE filename = ?', (filename,)).fetchone()
    if not file:
        flash('File not found.')
        return redirect(url_for('view_files'))

    if os.path.exists(file['encrypted_file_path']):
        os.remove(file['encrypted_file_path'])
        conn.execute('DELETE FROM files WHERE filename = ?', (filename,))
        conn.commit()
        conn.close()
        flash('File has been deleted.')
    else:
        flash('File not found.')
    return redirect(url_for('view_files'))

@app.route('/download_key/<key_id>')
@login_required
def download_key(key_id):
    conn = get_db_connection()
    key = conn.execute('SELECT * FROM keys WHERE id = ?', (key_id,)).fetchone()
    conn.close()
    if not key:
        flash('Key not found.')
        return redirect(url_for('view_keys'))

    return send_file(io.BytesIO(key['key_data'].encode('utf-8')), as_attachment=True, download_name='private_key.pem')

@app.route('/delete_key/<key_id>')
@login_required
def delete_key(key_id):
    conn = get_db_connection()
    conn.execute('DELETE FROM keys WHERE id = ?', (key_id,))
    conn.commit()
    conn.close()
    flash('Key has been deleted.')
    return redirect(url_for('view_keys'))

@app.route('/download_public_key/<key_id>')
@login_required
def download_public_key(key_id):
    conn = get_db_connection()
    key = conn.execute('SELECT * FROM keys WHERE id = ?', (key_id,)).fetchone()
    conn.close()
    if not key:
        flash('Key not found.')
        return redirect(url_for('view_keys'))

    public_key = serialization.load_pem_public_key(key['key_data'].encode('utf-8'))
    public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return send_file(io.BytesIO(public_key), as_attachment=True, download_name='public_key.pem')

@app.route('/delete_public_key/<key_id>')
@login_required
def delete_public_key(key_id):
    conn = get_db_connection()
    conn.execute('DELETE FROM keys WHERE id = ?', (key_id,))
    conn.commit()
    conn.close()
    flash('Public key has been deleted.')
    return redirect(url_for('view_keys'))

# Route to upload a file and securely hash it
@app.route('/upload_and_hash', methods=['POST'])
def upload_and_hash():
    uploaded_file = request.files['file']
    if uploaded_file:
        filename = secure_filename(uploaded_file.filename)
        file_path = './uploads/' + filename
        uploaded_file.save(file_path)

        # Hash the uploaded file using SHA256 by default
        sha256_hash = hash_file(file_path, algorithm='sha256')

        return f"File uploaded and hashed securely with SHA256: {sha256_hash}"
    else:
        return "No file uploaded"

# Route to compare two file hashes
@app.route('/compare_hashes', methods=['POST'])
def compare_hashes():
    file1_path = request.form['file1']
    file2_path = request.form['file2']
    algorithm = request.form.get('algorithm', 'sha256')

    # Hash both files
    hash1 = hash_file(file1_path, algorithm)
    hash2 = hash_file(file2_path, algorithm)

    if hash1 == hash2:
        return "Hashes match"
    else:
        return "Hashes do not match"
    

@app.route('/download_hashes')
def download_hashes():
    # Create a text file with hashes
    with open('hashes.txt', 'w') as f:
        f.write("Hashes:\n")
        f.write(f"SHA256: {hash_file('example.txt', 'sha256')}\n")
        f.write(f"MD5: {hash_file('example.txt', 'md5')}\n")

    # Send the file to the user for download
    return send_file('hashes.txt', as_attachment=True)

@app.route('/view_encrypted_files')
@login_required
def view_encrypted_files():
    conn = get_db_connection()
    user_files = conn.execute('SELECT * FROM files WHERE user_id = ?', (current_user.id,)).fetchall()
    conn.close()
    return render_template('view_encrypted_files.html', files=user_files)

@app.route('/view_hashes')
@login_required
def view_hashes():
    conn = get_db_connection()
    user_files = conn.execute('SELECT * FROM files WHERE user_id = ?', (current_user.id,)).fetchall()
    conn.close()
    return render_template('view_hashes.html', files=user_files)


if __name__ == '__main__':
    app.run(debug=True)
