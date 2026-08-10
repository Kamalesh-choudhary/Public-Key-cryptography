import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'pki.db')

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()

    cursor.executescript('''
        CREATE TABLE IF NOT EXISTS key_pairs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            algorithm TEXT NOT NULL,
            key_size TEXT,
            curve TEXT,
            public_key TEXT NOT NULL,
            private_key TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'active'
        );

        CREATE TABLE IF NOT EXISTS certificates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            serial_number TEXT UNIQUE NOT NULL,
            common_name TEXT NOT NULL,
            organization TEXT,
            country TEXT,
            subject_public_key_id INTEGER,
            issuer TEXT,
            valid_from TIMESTAMP,
            valid_to TIMESTAMP,
            certificate_pem TEXT NOT NULL,
            is_ca INTEGER DEFAULT 0,
            status TEXT DEFAULT 'active',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (subject_public_key_id) REFERENCES key_pairs(id)
        );

        CREATE TABLE IF NOT EXISTS signed_documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            document_name TEXT NOT NULL,
            document_hash TEXT NOT NULL,
            signature TEXT NOT NULL,
            signer_key_id INTEGER,
            signer_cert_id INTEGER,
            algorithm TEXT NOT NULL,
            signed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            verified INTEGER DEFAULT 0,
            FOREIGN KEY (signer_key_id) REFERENCES key_pairs(id),
            FOREIGN KEY (signer_cert_id) REFERENCES certificates(id)
        );

        CREATE TABLE IF NOT EXISTS ca_config (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            common_name TEXT NOT NULL,
            organization TEXT,
            country TEXT,
            certificate_id INTEGER,
            key_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (certificate_id) REFERENCES certificates(id),
            FOREIGN KEY (key_id) REFERENCES key_pairs(id)
        );
    ''')

    conn.commit()
    conn.close()
