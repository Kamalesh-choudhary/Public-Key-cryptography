from flask import Blueprint, request, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from database import get_db
import traceback

keys_bp = Blueprint('keys', __name__)

def generate_rsa_key(key_size):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    return private_key

def generate_ecc_key(curve_name):
    curves = {
        'P-256': ec.SECP256R1(),
        'P-384': ec.SECP384R1(),
        'P-521': ec.SECP521R1()
    }
    curve = curves.get(curve_name, ec.SECP256R1())
    private_key = ec.generate_private_key(curve, default_backend())
    return private_key

def serialize_private_key(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

@keys_bp.route('/generate', methods=['POST'])
def generate_key():
    try:
        data = request.json
        name = data.get('name', 'Unnamed Key')
        algorithm = data.get('algorithm', 'RSA')
        key_size = data.get('key_size', 2048)
        curve = data.get('curve', 'P-256')

        if algorithm == 'RSA':
            private_key = generate_rsa_key(int(key_size))
            public_key = private_key.public_key()
            priv_pem = serialize_private_key(private_key)
            pub_pem = serialize_public_key(public_key)
            db_curve = None
            db_key_size = str(key_size)
        elif algorithm == 'ECC':
            private_key = generate_ecc_key(curve)
            public_key = private_key.public_key()
            priv_pem = serialize_private_key(private_key)
            pub_pem = serialize_public_key(public_key)
            db_curve = curve
            db_key_size = None
        else:
            return jsonify({'error': 'Unsupported algorithm'}), 400

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO key_pairs (name, algorithm, key_size, curve, public_key, private_key)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (name, algorithm, db_key_size, db_curve, pub_pem, priv_pem))
        key_id = cursor.lastrowid
        conn.commit()
        conn.close()

        return jsonify({
            'success': True,
            'key_id': key_id,
            'name': name,
            'algorithm': algorithm,
            'key_size': db_key_size,
            'curve': db_curve,
            'public_key': pub_pem,
            'message': f'{algorithm} key pair generated successfully'
        })

    except Exception as e:
        return jsonify({'error': str(e), 'trace': traceback.format_exc()}), 500

@keys_bp.route('/list', methods=['GET'])
def list_keys():
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, name, algorithm, key_size, curve, created_at, status,
                   substr(public_key, 1, 100) as public_key_preview
            FROM key_pairs ORDER BY created_at DESC
        ''')
        keys = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return jsonify({'keys': keys})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@keys_bp.route('/<int:key_id>', methods=['GET'])
def get_key(key_id):
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM key_pairs WHERE id = ?', (key_id,))
        key = cursor.fetchone()
        conn.close()
        if not key:
            return jsonify({'error': 'Key not found'}), 404
        return jsonify(dict(key))
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@keys_bp.route('/<int:key_id>/delete', methods=['DELETE'])
def delete_key(key_id):
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('UPDATE key_pairs SET status = ? WHERE id = ?', ('revoked', key_id))
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'message': 'Key revoked successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
