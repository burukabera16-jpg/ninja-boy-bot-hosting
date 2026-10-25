import os
import json
from flask import Flask, jsonify, request

app = Flask(__name__)
JOBS = {}

def redact(value):
    if not value:
        return ""
    return "[REDACTED]" if any(k in value.upper() for k in ["TOKEN", "PASSWORD", "SECRET", "KEY"]) else value

@app.route('/health')
def health():
    return jsonify({"status": "ok"})

@app.route('/jobs/start', methods=['POST'])
def start_job():
    secret = request.headers.get('X-Worker-Secret')
    if secret != os.getenv('WORKER_API_SECRET', 'dev-worker-secret'):
        return jsonify({"error": "unauthorized"}), 401
    payload = request.get_json(force=True) or {}
    bot_id = payload.get('bot_id')
    if not bot_id:
        return jsonify({"error": "bot_id required"}), 400
    JOBS[str(bot_id)] = {"status": "RUNNING", "logs": ["job started"]}
    return jsonify({"status": "ok"})

@app.route('/jobs/stop/<int:bot_id>', methods=['POST'])
def stop_job(bot_id):
    secret = request.headers.get('X-Worker-Secret')
    if secret != os.getenv('WORKER_API_SECRET', 'dev-worker-secret'):
        return jsonify({"error": "unauthorized"}), 401
    JOBS[str(bot_id)] = {"status": "STOPPED", "logs": ["job stopped"]}
    return jsonify({"status": "ok"})

@app.route('/jobs/restart', methods=['POST'])
def restart_job():
    secret = request.headers.get('X-Worker-Secret')
    if secret != os.getenv('WORKER_API_SECRET', 'dev-worker-secret'):
        return jsonify({"error": "unauthorized"}), 401
    payload = request.get_json(force=True) or {}
    bot_id = payload.get('bot_id')
    JOBS[str(bot_id)] = {"status": "RUNNING", "logs": ["job restarted"]}
    return jsonify({"status": "ok"})

@app.route('/jobs/status/<int:bot_id>')
def status(bot_id):
    secret = request.headers.get('X-Worker-Secret')
    if secret != os.getenv('WORKER_API_SECRET', 'dev-worker-secret'):
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({"status": JOBS.get(str(bot_id), {}).get('status', 'UNKNOWN')})

@app.route('/jobs/logs/<int:bot_id>')
def logs(bot_id):
    secret = request.headers.get('X-Worker-Secret')
    if secret != os.getenv('WORKER_API_SECRET', 'dev-worker-secret'):
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({"logs": JOBS.get(str(bot_id), {}).get('logs', [])})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9001)
