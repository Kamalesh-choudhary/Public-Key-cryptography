from flask import Flask, render_template, request, jsonify, send_file
import os
from database import init_db
from routes.keys import keys_bp
from routes.ca import ca_bp
from routes.signing import signing_bp
from routes.dashboard import dashboard_bp

app = Flask(__name__)
app.secret_key = os.urandom(24)
# Initialize database
init_db()

# Register blueprints
app.register_blueprint(keys_bp, url_prefix='/api/keys')
app.register_blueprint(ca_bp, url_prefix='/api/ca')
app.register_blueprint(signing_bp, url_prefix='/api/sign')
app.register_blueprint(dashboard_bp, url_prefix='/api/dashboard')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/keys')
def keys_page():
    return render_template('keys.html')

@app.route('/ca')
def ca_page():
    return render_template('ca.html')

@app.route('/signing')
def signing_page():
    return render_template('signing.html')

if __name__ == '__main__':
    app.run(debug=True, port=5000)
