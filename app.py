from flask import Flask, render_template, request, send_file, url_for, jsonify, send_from_directory, after_this_request, current_app
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import os
from datetime import datetime
import zipfile
from base64 import b64encode, b64decode
import hashlib

app = Flask(__name__)

# Create a directory to hold temporary files
temp_dir = os.path.join(os.getcwd(), 'temp')
os.makedirs(temp_dir, exist_ok=True)

def calculate_hash(file_content):
    hasher = hashlib.sha256()
    hasher.update(file_content)
    return hasher.hexdigest()


def encrypt_file(file_content, password, filename):
    key = password.encode('utf-8')[:16]
    key = pad(key, AES.block_size)

    original_hash = calculate_hash(file_content)
    
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(file_content, AES.block_size))
    iv = cipher.iv
    
    # File name suffix
    encrypted_file_name = f"{os.path.splitext(filename)[0]}_encrypted{os.path.splitext(filename)[1]}"
    encrypted_file_path = os.path.join(temp_dir, encrypted_file_name)
    
    with open(encrypted_file_path, 'wb') as f:
        f.write(iv + ct_bytes + original_hash.encode())
    print(f"File written to {encrypted_file_path}")
    
    return encrypted_file_path, encrypted_file_name

def decrypt_file(encrypted_content, password, filename):
    key = password.encode('utf-8')[:16]
    key = pad(key, AES.block_size)

    stored_hash = encrypted_content[-64:].decode()
    encrypted_content = encrypted_content[:-64]
    
    iv = encrypted_content[:16]
    ct_bytes = encrypted_content[16:]
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct_bytes), AES.block_size)
    
    decrypted_hash = calculate_hash(pt)

    if decrypted_hash != stored_hash:
        raise ValueError("File integrity compromised.")
        
    # Desuffix
    decrypted_file_name = f"{os.path.splitext(filename)[0]}_decrypted{os.path.splitext(filename)[1]}"
    decrypted_file_path = os.path.join(temp_dir, decrypted_file_name)
    
    with open(decrypted_file_path, 'wb') as f:
        f.write(pt)
    
    return decrypted_file_path, decrypted_file_name

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/downloads/<path:filename>')
def download_file(filename):
    base_directory = temp_dir

    # Check whether files exist in the temp directory or any of its subdirectories
    full_path = os.path.join(base_directory, filename)
    if os.path.isfile(full_path):
        # Calculates the path of the file directory relative to base_directory
        directory = os.path.dirname(full_path)
        # Gets the base name of the file (without path)
        basename = os.path.basename(filename)
        return send_from_directory(directory, basename, as_attachment=True)
    else:
        return "File not found", 404

    # return send_from_directory(temp_dir, filename, as_attachment=True)

@app.route('/encrypt', methods=['POST'])
def handle_encrypt():
    file = request.files['file']
    password = request.form['password']
    secure_original_name = secure_filename(file.filename)
    
    encrypted_content, encrypted_file_name = encrypt_file(file.read(), password, secure_original_name)
    encrypted_file_path = os.path.join(temp_dir, encrypted_file_name)
    
    # @after_this_request
    # def remove_file(response):
    #     try:
    #         os.remove(encrypted_file_path)
    #     except Exception as error:
    #         app.logger.error("Error removing or closing downloaded file handle", error)
    #     return response

    return jsonify({'download_url': url_for('download_file', filename=encrypted_file_name)})

    # return send_file(encrypted_file_path, as_attachment=True, download_name=encrypted_file_name)

@app.route('/decrypt', methods=['POST'])
def handle_decrypt():
    file = request.files['file']
    password = request.form['password']
    secure_original_name = secure_filename(file.filename)

    try:
        decrypted_content, decrypted_file_name = decrypt_file(file.read(), password, secure_original_name)
    except ValueError:
        response = jsonify({'error': 'Incorrect password, unable to decrypt.'})
        response.status_code = 400
        return response
    
    decrypted_file_path = os.path.join(temp_dir, decrypted_file_name)
    
    # @after_this_request
    # def remove_file(response):
    #     try:
    #         os.remove(decrypted_file_path)
    #     except Exception as error:
    #         app.logger.error("Error removing or closing downloaded file handle", error)
    #     return response

    return jsonify({'download_url': url_for('download_file', filename=decrypted_file_name)})
    # return send_file(decrypted_file_path, as_attachment=True, download_name=decrypted_file_name)

@app.route('/generate_key', methods=['GET'])
def generate_key():
    # Generate key pair
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    
    # Use the current time as the directory name to make sure it's different each time
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    key_dir = os.path.join('keys', timestamp)
    os.makedirs(key_dir, exist_ok=True)

    # Save the key with a unique file name
    private_keyN = timestamp + '_private.pem'
    public_keyN = timestamp + '_public.pem'
    private_key_file = os.path.join(key_dir, private_keyN)
    public_key_file = os.path.join(key_dir, public_keyN)
    
    # Writes the key to a file
    with open(private_key_file, 'wb') as priv_file:
        priv_file.write(private_key)
    with open(public_key_file, 'wb') as pub_file:
        pub_file.write(public_key)
    
    zip_filename = f"{timestamp}_keys.zip"
    zip_path = os.path.join(key_dir, zip_filename)
    with zipfile.ZipFile(zip_path, 'w') as zipf:
        zipf.write(private_key_file, private_keyN)
        zipf.write(public_key_file, public_keyN)

    return send_file(zip_path, as_attachment=True, download_name=zip_filename)
    # return jsonify({'download_url': url_for('download_file', filename=zip_filename)})

@app.route('/encrypt_with_public', methods=['POST'])
def encrypt_with_public():
    # Get the uploaded file and public key
    file = request.files['file']
    public_key_uploaded = request.files['public_key']
    
    # Separate file name and extension
    original_filename, file_extension = os.path.splitext(secure_filename(file.filename))
    
    try:
        
        # Loading public key
        public_key = RSA.import_key(public_key_uploaded.read())
        cipher_rsa = PKCS1_OAEP.new(public_key)
        
        # Generate AES keys
        aes_key = get_random_bytes(16)
        
        # Use AES keys to encrypt file data (The file which needs to be encrypted is too large(plaintext is too long) to encrpted directly with .pem file(the public key))
        cipher_aes = AES.new(aes_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(file.read())
        
        # Use the RSA public key to encrypt the AES key
        enc_aes_key = cipher_rsa.encrypt(aes_key)
        
        # Merge the encrypted AES key, nonce, tag, and encrypted data
        encrypted_data = b64encode(enc_aes_key + cipher_aes.nonce + tag + ciphertext)

        encrypted_files_directory = os.path.join('temp', 'PubK_encrypted_files')
        os.makedirs(encrypted_files_directory, exist_ok=True)
        
        # Save encrypted data to a file while preserving the extension of the original file
        encrypted_file_name = f"{original_filename}_encrypted{file_extension}"
        encrypted_file_path = os.path.join(encrypted_files_directory, encrypted_file_name)
        
        with open(encrypted_file_path, 'wb') as encrypted_file:
            encrypted_file.write(encrypted_data)

        download_url = url_for('download_file', filename=os.path.join('PubK_encrypted_files', encrypted_file_name), _external=True)
        return jsonify({'download_url': download_url}), 200

    except (ValueError, TypeError) as e:
        return jsonify({'error': str(e)}), 400
    
    # return send_file(encrypted_file_path, as_attachment=True, download_name=encrypted_file_name)

@app.route('/decrypt_with_private', methods=['POST'])
def decrypt_with_private():
    # Get the uploaded encrypted file and private key
    encrypted_file = request.files['encrypted_file']
    private_key_uploaded = request.files['private_key']
    original_filename = secure_filename(encrypted_file.filename)  

    # Separate the original file name from the extension
    original_filename, original_extension = os.path.splitext(secure_filename(encrypted_file.filename))
    
    # Remove the added '_encrypted' part of the file name
    if original_filename.endswith('_encrypted'):
        original_filename = original_filename[:-(len('_encrypted'))]
    
    
    try:
        # Load the private key
        private_key = RSA.import_key(private_key_uploaded.read())
        cipher_rsa = PKCS1_OAEP.new(private_key)

        # Read encrypted data and decode it
        encrypted_data = b64decode(encrypted_file.read())
        enc_aes_key, nonce, tag, ciphertext = \
            encrypted_data[:256], encrypted_data[256:272], encrypted_data[272:288], encrypted_data[288:]

        # Decrypt the AES key
        aes_key = cipher_rsa.decrypt(enc_aes_key)

        # Use AES keys to decrypt file data
        cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce)
        try:
            data = cipher_aes.decrypt_and_verify(ciphertext, tag)
        except ValueError as e:
            # Decryption failed. Possible password error
            return jsonify({'error': 'Decryption failed. Incorrect private key or corrupted data.'}), 400


        decrypted_files_directory = os.path.join('temp', 'PrvK_decrypted_files')
        os.makedirs(decrypted_files_directory, exist_ok=True)

        decrypted_file_name = f"{os.path.splitext(original_filename)[0]}_decrypted"

        # Save decrypted data to file
        decrypted_file_path = os.path.join(decrypted_files_directory, decrypted_file_name + original_extension)
        with open(decrypted_file_path, 'wb') as decrypted_file:
            decrypted_file.write(data)

        download_url = url_for('download_file', filename=os.path.join('PrvK_decrypted_files', decrypted_file_name + original_extension), _external=True)
        return jsonify({'download_url': download_url}), 200

    except (ValueError, TypeError) as e:
        return jsonify({'error': str(e)}), 400
    
    # Return the decrypted file
    # return send_file(decrypted_file_path, as_attachment=True, download_name=decrypted_file_name + original_extension)


if __name__ == "__main__":
    app.run(debug=True)
