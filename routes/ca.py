from flask import Blueprint, request, jsonify
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate
from database import get_db
import datetime
import uuid
import traceback

ca_bp = Blueprint('ca', __name__)

def load_private_key(pem_str):
    return serialization.load_pem_private_key(
        pem_str.encode(), password=None, backend=default_backend()
    )

def build_name(cn, org, country):
    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
    if org:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, org))
    if country:
        attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country[:2].upper()))
    return x509.Name(attrs)

@ca_bp.route('/setup', methods=['POST'])
def setup_ca():
    try:
        data = request.json
        key_id = data.get('key_id')
        cn = data.get('common_name', 'My Root CA')
        org = data.get('organization', '')
        country = data.get('country', 'US')
        validity_days = int(data.get('validity_days', 3650))

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM key_pairs WHERE id = ?', (key_id,))
        key_row = cursor.fetchone()
        if not key_row:
            conn.close()
            return jsonify({'error': 'Key not found'}), 404

        private_key = load_private_key(key_row['private_key'])
        public_key = private_key.public_key()

        subject = issuer = build_name(cn, org, country)
        serial = int(uuid.uuid4()) & 0xFFFFFFFFFFFFFFFF
        now = datetime.datetime.utcnow()

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(public_key)
            .serial_number(serial)
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=validity_days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        )

        if isinstance(private_key, rsa.RSAPrivateKey):
            cert = builder.sign(private_key, hashes.SHA256(), default_backend())
        else:
            cert = builder.sign(private_key, hashes.SHA256(), default_backend())

        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')

        cursor.execute('''
            INSERT INTO certificates (serial_number, common_name, organization, country,
                subject_public_key_id, issuer, valid_from, valid_to, certificate_pem, is_ca)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
        ''', (str(serial), cn, org, country, key_id, cn, now, now + datetime.timedelta(days=validity_days), cert_pem))
        cert_id = cursor.lastrowid

        cursor.execute('''
            INSERT OR REPLACE INTO ca_config (common_name, organization, country, certificate_id, key_id)
            VALUES (?, ?, ?, ?, ?)
        ''', (cn, org, country, cert_id, key_id))

        conn.commit()
        conn.close()

        return jsonify({
            'success': True,
            'cert_id': cert_id,
            'serial_number': str(serial),
            'common_name': cn,
            'certificate_pem': cert_pem,
            'valid_from': now.isoformat(),
            'valid_to': (now + datetime.timedelta(days=validity_days)).isoformat(),
            'message': 'Root CA created successfully'
        })

    except Exception as e:
        return jsonify({'error': str(e), 'trace': traceback.format_exc()}), 500

@ca_bp.route('/sign-csr', methods=['POST'])
def sign_certificate():
    try:
        data = request.json
        subject_key_id = data.get('subject_key_id')
        cn = data.get('common_name', 'End Entity')
        org = data.get('organization', '')
        country = data.get('country', 'US')
        validity_days = int(data.get('validity_days', 365))

        conn = get_db()
        cursor = conn.cursor()

        # Get CA config
        cursor.execute('SELECT * FROM ca_config ORDER BY id DESC LIMIT 1')
        ca_conf = cursor.fetchone()
        if not ca_conf:
            conn.close()
            return jsonify({'error': 'No CA configured. Please setup a Root CA first.'}), 400

        # Get CA key & cert
        cursor.execute('SELECT * FROM key_pairs WHERE id = ?', (ca_conf['key_id'],))
        ca_key_row = cursor.fetchone()
        cursor.execute('SELECT * FROM certificates WHERE id = ?', (ca_conf['certificate_id'],))
        ca_cert_row = cursor.fetchone()

        # Get subject key
        cursor.execute('SELECT * FROM key_pairs WHERE id = ?', (subject_key_id,))
        subject_key_row = cursor.fetchone()
        if not subject_key_row:
            conn.close()
            return jsonify({'error': 'Subject key not found'}), 404

        ca_private_key = load_private_key(ca_key_row['private_key'])
        ca_cert = load_pem_x509_certificate(ca_cert_row['certificate_pem'].encode(), default_backend())
        subject_private_key = load_private_key(subject_key_row['private_key'])
        subject_public_key = subject_private_key.public_key()

        subject_name = build_name(cn, org, country)
        serial = int(uuid.uuid4()) & 0xFFFFFFFFFFFFFFFF
        now = datetime.datetime.utcnow()

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject_name)
            .issuer_name(ca_cert.subject)
            .public_key(subject_public_key)
            .serial_number(serial)
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=validity_days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(subject_public_key), critical=False)
        )

        cert = builder.sign(ca_private_key, hashes.SHA256(), default_backend())
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')

        cursor.execute('''
            INSERT INTO certificates (serial_number, common_name, organization, country,
                subject_public_key_id, issuer, valid_from, valid_to, certificate_pem, is_ca)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
        ''', (str(serial), cn, org, country, subject_key_id, ca_conf['common_name'],
              now, now + datetime.timedelta(days=validity_days), cert_pem))
        cert_id = cursor.lastrowid
        conn.commit()
        conn.close()

        return jsonify({
            'success': True,
            'cert_id': cert_id,
            'serial_number': str(serial),
            'common_name': cn,
            'issuer': ca_conf['common_name'],
            'certificate_pem': cert_pem,
            'valid_from': now.isoformat(),
            'valid_to': (now + datetime.timedelta(days=validity_days)).isoformat(),
            'message': 'Certificate signed by CA successfully'
        })

    except Exception as e:
        return jsonify({'error': str(e), 'trace': traceback.format_exc()}), 500

@ca_bp.route('/certificates', methods=['GET'])
def list_certificates():
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, serial_number, common_name, organization, country,
                   issuer, valid_from, valid_to, is_ca, status, created_at
            FROM certificates ORDER BY created_at DESC
        ''')
        certs = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return jsonify({'certificates': certs})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@ca_bp.route('/certificates/<int:cert_id>', methods=['GET'])
def get_certificate(cert_id):
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM certificates WHERE id = ?', (cert_id,))
        cert = cursor.fetchone()
        conn.close()
        if not cert:
            return jsonify({'error': 'Certificate not found'}), 404
        return jsonify(dict(cert))
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@ca_bp.route('/certificates/<int:cert_id>/revoke', methods=['POST'])
def revoke_certificate(cert_id):
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('UPDATE certificates SET status = ? WHERE id = ?', ('revoked', cert_id))
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'message': 'Certificate revoked successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@ca_bp.route('/status', methods=['GET'])
def ca_status():
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM ca_config ORDER BY id DESC LIMIT 1')
        ca_conf = cursor.fetchone()
        if not ca_conf:
            conn.close()
            return jsonify({'configured': False})
        cursor.execute('SELECT * FROM certificates WHERE id = ?', (ca_conf['certificate_id'],))
        ca_cert = cursor.fetchone()
        conn.close()
        return jsonify({'configured': True, 'ca': dict(ca_conf), 'certificate': dict(ca_cert) if ca_cert else None})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
