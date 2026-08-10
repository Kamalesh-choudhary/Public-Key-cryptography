from flask import Blueprint, request, jsonify
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.hazmat.backends import default_backend
from database import get_db
import base64
import hashlib
import traceback

signing_bp = Blueprint('signing', __name__)

def load_private_key(pem_str):
    return serialization.load_pem_private_key(
        pem_str.encode(), password=None, backend=default_backend()
    )

def load_public_key(pem_str):
    return serialization.load_pem_public_key(
        pem_str.encode(), backend=default_backend()
    )

@signing_bp.route('/sign', methods=['POST'])
def sign_document():
    try:
        data = request.json
        document_content = data.get('document_content', '')
        document_name = data.get('document_name', 'document.txt')
        key_id = data.get('key_id')
        cert_id = data.get('cert_id')

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM key_pairs WHERE id = ?', (key_id,))
        key_row = cursor.fetchone()
        if not key_row:
            conn.close()
            return jsonify({'error': 'Key not found'}), 404

        private_key = load_private_key(key_row['private_key'])

        # Hash document
        doc_bytes = document_content.encode('utf-8')
        doc_hash = hashlib.sha256(doc_bytes).hexdigest()

        # Sign
        from cryptography.hazmat.primitives.asymmetric import rsa as rsa_module
        if isinstance(private_key, rsa_module.RSAPrivateKey):
            signature = private_key.sign(doc_bytes, padding.PKCS1v15(), hashes.SHA256())
            algo_used = f"RSA-{key_row['key_size']}-SHA256"
        else:
            signature = private_key.sign(doc_bytes, ec.ECDSA(hashes.SHA256()))
            algo_used = f"ECDSA-{key_row['curve']}-SHA256"

        signature_b64 = base64.b64encode(signature).decode('utf-8')

        cursor.execute('''
            INSERT INTO signed_documents (document_name, document_hash, signature,
                signer_key_id, signer_cert_id, algorithm)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (document_name, doc_hash, signature_b64, key_id, cert_id, algo_used))
        doc_id = cursor.lastrowid
        conn.commit()
        conn.close()

        return jsonify({
            'success': True,
            'doc_id': doc_id,
            'document_name': document_name,
            'document_hash': doc_hash,
            'signature': signature_b64,
            'algorithm': algo_used,
            'message': 'Document signed successfully'
        })

    except Exception as e:
        return jsonify({'error': str(e), 'trace': traceback.format_exc()}), 500

@signing_bp.route('/verify', methods=['POST'])
def verify_document():
    try:
        data = request.json
        document_content = data.get('document_content', '')
        signature_b64 = data.get('signature', '')
        key_id = data.get('key_id')

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM key_pairs WHERE id = ?', (key_id,))
        key_row = cursor.fetchone()
        if not key_row:
            conn.close()
            return jsonify({'error': 'Key not found'}), 404

        public_key = load_public_key(key_row['public_key'])
        doc_bytes = document_content.encode('utf-8')
        signature = base64.b64decode(signature_b64)

        from cryptography.hazmat.primitives.asymmetric import rsa as rsa_module
        try:
            if isinstance(public_key, rsa_module.RSAPublicKey):
                public_key.verify(signature, doc_bytes, padding.PKCS1v15(), hashes.SHA256())
            else:
                public_key.verify(signature, doc_bytes, ec.ECDSA(hashes.SHA256()))
            verified = True
            message = 'Signature is VALID ✓'
        except Exception:
            verified = False
            message = 'Signature is INVALID ✗'

        # Update verification status in DB
        doc_hash = hashlib.sha256(doc_bytes).hexdigest()
        cursor.execute('''
            UPDATE signed_documents SET verified = ? WHERE document_hash = ? AND signer_key_id = ?
        ''', (1 if verified else 0, doc_hash, key_id))
        conn.commit()
        conn.close()

        return jsonify({
            'success': True,
            'verified': verified,
            'message': message,
            'document_hash': doc_hash
        })

    except Exception as e:
        return jsonify({'error': str(e), 'trace': traceback.format_exc()}), 500

@signing_bp.route('/documents', methods=['GET'])
def list_documents():
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT sd.id, sd.document_name, sd.document_hash, sd.algorithm,
                   sd.signed_at, sd.verified,
                   kp.name as signer_name, kp.algorithm as key_algo,
                   c.common_name as cert_cn
            FROM signed_documents sd
            LEFT JOIN key_pairs kp ON sd.signer_key_id = kp.id
            LEFT JOIN certificates c ON sd.signer_cert_id = c.id
            ORDER BY sd.signed_at DESC
        ''')
        docs = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return jsonify({'documents': docs})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
