from flask import Flask, render_template
from flask_socketio import SocketIO
import threading
import watcher
from datetime import datetime

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

# Stats
stats = {
    'total_scanned': 0,
    'threats_blocked': 0
}

def event_callback(data):
    # Update Stats
    stats['total_scanned'] += 1
    if data['is_threat']:
        stats['threats_blocked'] += 1
        
    # Add timestamp
    data['timestamp'] = datetime.now().strftime("%H:%M:%S")
    
    # Emit to all clients
    socketio.emit('new_event', data)
    socketio.emit('update_stats', stats)

def start_watcher_thread():
    watcher.run_watcher(event_callback)

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    # Start watcher in background thread
    t = threading.Thread(target=start_watcher_thread, daemon=True)
    t.start()
    
    print("Starting Web Dashboard on port 5000...")
    socketio.run(app, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)
