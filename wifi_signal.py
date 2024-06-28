from flask import Blueprint, jsonify
import subprocess
import re

ap = Blueprint('wifi_signal', __name__)

def get_wifi_signal_strength():
    try:
        # Example for Windows
        result = subprocess.run(["netsh", "wlan", "show", "interfaces"], capture_output=True, text=True)
        output = result.stdout

        match = re.search(r"Signal\s*:\s*(\d+)", output)
        if match:
            signal_strength = int(match.group(1))
            dBm = (signal_strength / 2) - 100
            return dBm
        else:
            return None
    except Exception as e:
        print(f"Error: {e}")
        return None

@ap.route('/api/signal_strength', methods=['GET'])
def signal_strength():
    strength = get_wifi_signal_strength()
    if strength is not None:
        return jsonify({'signal_strength': strength})
    else:
        return jsonify({'error': 'Could not determine signal strength'}), 500
