from flask import Blueprint, jsonify
from database import get_db

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/stats', methods=['GET'])
def get_stats():
    try:
        conn = get_db()
        cursor = conn.cursor()

        cursor.execute('SELECT COUNT(*) as count FROM key_pairs WHERE status = "active"')
        active_keys = cursor.fetchone()['count']

        cursor.execute('SELECT COUNT(*) as count FROM key_pairs WHERE status = "revoked"')
        revoked_keys = cursor.fetchone()['count']

        cursor.execute('SELECT COUNT(*) as count FROM certificates WHERE status = "active"')
        active_certs = cursor.fetchone()['count']

        cursor.execute('SELECT COUNT(*) as count FROM certificates WHERE status = "revoked"')
        revoked_certs = cursor.fetchone()['count']

        cursor.execute('SELECT COUNT(*) as count FROM signed_documents')
        total_docs = cursor.fetchone()['count']

        cursor.execute('SELECT COUNT(*) as count FROM signed_documents WHERE verified = 1')
        verified_docs = cursor.fetchone()['count']

        cursor.execute('SELECT * FROM ca_config ORDER BY id DESC LIMIT 1')
        ca_conf = cursor.fetchone()

        cursor.execute('''
            SELECT kp.name, kp.algorithm, kp.created_at
            FROM key_pairs kp ORDER BY kp.created_at DESC LIMIT 5
        ''')
        recent_keys = [dict(r) for r in cursor.fetchall()]

        cursor.execute('''
            SELECT sd.document_name, sd.algorithm, sd.signed_at, kp.name as signer
            FROM signed_documents sd
            LEFT JOIN key_pairs kp ON sd.signer_key_id = kp.id
            ORDER BY sd.signed_at DESC LIMIT 5
        ''')
        recent_docs = [dict(r) for r in cursor.fetchall()]

        cursor.execute('SELECT algorithm, COUNT(*) as count FROM key_pairs GROUP BY algorithm')
        algo_dist = [dict(r) for r in cursor.fetchall()]

        conn.close()

        return jsonify({
            'stats': {
                'active_keys': active_keys,
                'revoked_keys': revoked_keys,
                'active_certs': active_certs,
                'revoked_certs': revoked_certs,
                'total_docs': total_docs,
                'verified_docs': verified_docs,
                'ca_configured': ca_conf is not None,
                'ca_name': ca_conf['common_name'] if ca_conf else None
            },
            'recent_keys': recent_keys,
            'recent_docs': recent_docs,
            'algo_distribution': algo_dist
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
