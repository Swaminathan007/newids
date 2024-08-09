#! /usr/bin/python3
##########################IMPORTS##############################################33
from flask import *
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_socketio import SocketIO,emit
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import subprocess
import threading
import time
from datetime import datetime,timedelta
import requests
from requests.auth import HTTPBasicAuth
from collections import deque
from queue import Queue
import argparse
import pty
import os
import select
import termios
import struct
import fcntl
import shlex
import logging
import sys
import boto3
from wifi_signal import ap as wifi_signal_blueprint
import zipfile
from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from models import *
import psutil
############################################################################

###################################THREADS###############################
class LogThread(threading.Thread):
    def __init__(self):
        super(LogThread,self).__init__()
        self._stop_event = threading.Event()
        self.__bucket_name = "ottrafficlogs"
        self.__log_path = "/home/swaminathan/IDS1/static/csv"
        self.__zipped_log_path = "/home/swaminathan/IDS1/static/zippedlogs"
        self.__client = boto3.client("s3")
    def run(self):
        while True:
            cur_time = datetime.now()
            cur_min = cur_time.minute
            if(cur_min%30 == 0):
                zip_file_name = f"Log-{str(cur_time-timedelta(minutes=30))} - {str(cur_time)}.zip"
                self.store_logs_locally(zip_file_name)
                self.store_logs_aws(zip_file_name)
                message = f"Logs have been stored: {zip_file_name}"
                socketio.emit('log_update', {'message': message}, broadcast=True)
                print("Logs stored successfully")
                time.sleep(60)
            time.sleep(1)
    def store_logs_locally(self,zip_file_name):
        with zipfile.ZipFile(f"{self.__zipped_log_path}/{zip_file_name}", 'w') as zipf:
            for foldername, subfolders, filenames in os.walk(self.__log_path):
                for filename in filenames:
                    file_path = os.path.join(foldername, filename)
                    zipf.write(file_path, os.path.relpath(file_path, self.__log_path))
    def store_logs_aws(self,zip_file_name):
        try:
            with open(f"{self.__zipped_log_path}/{zip_file_name}", "rb") as f:
                self.__client.upload_fileobj(f, "ottrafficlogs", zip_file_name)
        except:
            socketio.emit("log_update",{"message":"Error connecting to AWS"},broadcast=True)
###########################################################################################
#SNIFFING GLOBALS
CAPTURES_DIR = os.path.join(os.getcwd(), 'static', 'captures')
os.makedirs(CAPTURES_DIR, exist_ok=True)
sniffing_event = Event()
sniffing_thread = None
captured_packets = []
start_time = None
filename = None
####################333

#THREADS GLOBALS
log_thread = None


#FLASK GLOBALS
app = Flask(__name__)
app.secret_key = 'my_secret_key'
app.config['SESSION_TYPE'] = 'filesystem'
app.config["fd"] = None
app.config["child_pid"] = None
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
socketio = SocketIO(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)


##########################################################
#DATABASE MODELS FOR SQL


class User(UserMixin,db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, nullable=False, unique=True)
    password = db.Column(db.String, nullable=False, default=True)

class Firewall_Ip(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String, nullable=False, unique=True)

#LOGIN USER##################
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
#############################
##############################FIREWALL GLOBALS##########################################




######################################JARA AND DASHBOARD GLOBALS######################################
python_clients = []
messages = []
#All interfaces
interfaces = []
previous_stats = {}
jara_clients = {}
###########################################




##########################
###########################################TRAFFIC PART###############################
def get_interface_list():
    stats = psutil.net_io_counters(pernic=True)
    return list(stats.keys())

def get_network_stats():
    global previous_stats
    current_stats = psutil.net_io_counters(pernic=True)
    network_stats = {}
    
    for iface in current_stats.keys():
        if iface in previous_stats:
            prev_sent = previous_stats[iface].packets_sent
            prev_recv = previous_stats[iface].packets_recv
            sent_per_sec = current_stats[iface].packets_sent - prev_sent
            recv_per_sec = current_stats[iface].packets_recv - prev_recv
        else:
            sent_per_sec = 0
            recv_per_sec = 0
        
        network_stats[iface] = {
            'packets_sent': sent_per_sec,
            'packets_recv': recv_per_sec
        }
    
    previous_stats = current_stats
    return network_stats



def emit_network_stats():
    while True:
        socketio.emit('network_stats', get_network_stats())
        time.sleep(1)


@app.route('/')
@login_required
def home():
    global interfaces
    interfaces = get_interface_list()
    print(interfaces)
    return render_template('index.html',interfaces=interfaces)

@app.route('/network_stats')
@login_required
def network_stats():
    stats = get_network_stats()
    print(stats)
    return jsonify(stats)
####################################################################################################


##################################################FIREWALL##############################


def get_iptables_rules():
    try:
        result = subprocess.run(['sudo', 'iptables', '-L', '-n', '-v'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            raise Exception(result.stderr)
        return result.stdout
    except Exception as e:
        return str(e)

def add_iptables_rule(rule):
    try:
        subprocess.run(['sudo', 'iptables'] + rule.split(), check=True)
    except subprocess.CalledProcessError as e:
        return str(e)
    return None

@app.route('/firewall', methods=['GET', 'POST'])
def firewall():
    if request.method == 'POST':
        ip = request.form.get('ip')
        direction = request.form.get('direction')
        port = request.form.get('port')
        protocol = request.form.get('protocol')
        action = request.form.get('action')

        if ip and direction and action:
            rule = f"-A {direction} -s {ip} -j {action}" if direction == 'INPUT' else f"-A {direction} -d {ip} -j {action}"
            if port and protocol:
                rule += f" -p {protocol} --dport {port}"
            error = add_iptables_rule(rule)
            if error:
                flash(f"Error: {error}", 'danger')
            else:
                flash("Rule added successfully!", 'success')
        else:
            flash("Please fill in all required fields.", 'danger')
        return redirect(url_for('firewall'))

    rules = get_iptables_rules()
    return render_template('firewall.html', rules=rules)

###################################################################################


###########################################USER AUTHENTICATION###################################
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('home'))
        flash('Invalid username or password')
    return render_template('login.html')
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))
    
###############################################################################


#######################USER ADD#############################
@app.route("/adduser", methods=["GET", "POST"])
@login_required
def adduser():
    return render_template("adduser.html")
############################################################

##############################SNIFFING###########################################

def get_protocol(packet):
    if IP in packet:
        return packet[IP].proto
    elif IPv6 in packet:
        return packet[IPv6].nh
    return "Unknown"

def packet_callback(packet):
    global captured_packets
    if sniffing_event.is_set():
        captured_packets.append(packet)

        if IP in packet or IPv6 in packet:
            src_ip = packet[0][1].src
            dst_ip = packet[0][1].dst
            protocol = get_protocol(packet)
            payload = packet[Raw].load.decode('utf-8', errors='ignore') if Raw in packet else "No payload"
            packet_details = str(packet)
            iface = packet.sniffed_on
            socketio.emit('new_packet', {
                'packet_details': packet_details,
                'timestamp': str(datetime.now()),
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'protocol': protocol,
                'interface': iface,
                'payload': payload
            })

def start_sniffing():
    global start_time, captured_packets
    start_time = datetime.now()
    captured_packets = []
    interfaces = conf.ifaces.data.keys()
    try:
        sniff(iface=list(interfaces), prn=packet_callback, store=False, stop_filter=lambda x: not sniffing_event.is_set())
    except Exception as e:
        print(f"Error during sniffing: {e}")

def stop_sniffing():
    global start_time, captured_packets, filename
    end_time = datetime.now()
    start_time_str = start_time.strftime('%Y%m%d%H%M%S')
    end_time_str = end_time.strftime('%Y%m%d%H%M%S')
    filename = f'capture_{start_time_str}-{end_time_str}.pcap'
    file_path = os.path.join(CAPTURES_DIR, filename)
    wrpcap(file_path, captured_packets)
    print(f"Saved packets to {file_path}")
    return filename

@socketio.on('start_sniffing')
def handle_start_sniffing():
    global sniffing_thread, start_time
    sniffing_event.set()
    if sniffing_thread is None or not sniffing_thread.is_alive():
        start_time = datetime.now()
        sniffing_thread = Thread(target=start_sniffing)
        sniffing_thread.start()

@socketio.on('stop_sniffing')
def handle_stop_sniffing():
    global sniffing_thread
    sniffing_event.clear()
    if sniffing_thread and sniffing_thread.is_alive():
        sniffing_thread.join()
    filename = stop_sniffing()
    emit('download_file', filename)
@app.route('/<filename>')
def download_capture(filename):
    file_path = os.path.join(CAPTURES_DIR, filename)
    return send_file(file_path, as_attachment=True)

@app.route('/sniffer')
def sniffer():
    return render_template('sniffer.html')


############################################################################

##################################TERMINAL#####################################



def set_winsize(fd, row, col, xpix=0, ypix=0):
    logging.debug("setting window size with termios")
    winsize = struct.pack("HHHH", row, col, xpix, ypix)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)


def read_and_forward_pty_output():
    max_read_bytes = 1024 * 20
    while True:
        socketio.sleep(0.01)
        if app.config["fd"]:
            timeout_sec = 0
            (data_ready, _, _) = select.select([app.config["fd"]], [], [], timeout_sec)
            if data_ready:
                output = os.read(app.config["fd"], max_read_bytes).decode(errors="ignore")
                socketio.emit("pty-output", {"output": output}, namespace="/pty")
@app.route("/terminal")
@login_required
def terminal():
    return render_template("terminal.html")


@socketio.on("pty-input", namespace="/pty")
def pty_input(data):
    """write to the child pty. The pty sees this as if you are typing in a real
    terminal.
    """
    if app.config["fd"]:
        logging.debug("received input from browser: %s" % data["input"])
        os.write(app.config["fd"], data["input"].encode())

@socketio.on("resize", namespace="/pty")
def resize(data):
    if app.config["fd"]:
        logging.debug(f"Resizing window to {data['rows']}x{data['cols']}")
        set_winsize(app.config["fd"], data["rows"], data["cols"])


@socketio.on("connect", namespace="/pty")
def connect():
    """new client connected"""
    logging.info("terminal connected")
    if app.config["child_pid"]:
        # already started child process, don't start another
        return

    # create child process attached to a pty we can read from and write to
    (child_pid, fd) = pty.fork()
    if child_pid == 0:
        # this is the child process fork.
        # anything printed here will show up in the pty, including the output
        # of this subprocess
        home_directory = os.path.expanduser("~")
        os.chdir(home_directory)  # Change to the user's home directory
        subprocess.run(app.config["cmd"])
    else:
        # this is the parent process fork.
        # store child fd and pid
        app.config["fd"] = fd
        app.config["child_pid"] = child_pid
        set_winsize(fd, 50, 50)
        cmd = " ".join(shlex.quote(c) for c in app.config["cmd"])
        # logging/print statements must go after this because... I have no idea why
        # but if they come before the background task never starts
        socketio.start_background_task(target=read_and_forward_pty_output)

        logging.info(f"child pid is {child_pid}")
        logging.info(
            f"starting background task with command `{cmd}` to continuously read "
            "and forward pty output to client"
        )
        logging.info("task started")
####################################SYSTEM DASHBOARD#####################################################

@app.route("/sysinfo")
@login_required
def sysinfo():
    return render_template("sysinfo.html")

@app.route('/utilization_stats')
@login_required
def get_utilization():
    cpu_percent = psutil.cpu_percent(interval=1)
    memory_info = psutil.virtual_memory()
    memory_percent = memory_info.percent
    utilization = {
        'cpu': cpu_percent,
        'memory': memory_percent
    }
    
    return jsonify(utilization)
############################################################################################

#########################################JARA##############################################

@app.route('/jara', methods=["GET"])
def jara_clients_display():
    print(jara_clients)
    return render_template('jara_clients.html',jara_clients = jara_clients)
@app.route("/jara/client/<jara_client>")
def jara_client_display(jara_client):
    jara_client_current = jara_clients[jara_client]
    jara_client_interfaces = jara_client_current["interfaces"]
    return render_template("jara_client.html",jara_client_current=jara_client_current,jara_client=jara_client,interfaces=jara_client_interfaces)
@app.route("/jara/client/<jara_client>/network_stats",methods=["GET"])
def client_network_stats(jara_client):
    try:
        stats = jara_clients[jara_client]["traffic"]
        return jsonify(stats)
    except:
        return {}
@app.route("/jara/client/<jara_client>/analyse_file/<file>")
def analyse_file(jara_client,file):
    socketio.emit('analyse_file',{'file':file},room=jara_client)
    return redirect(url_for("jara_clients_display"))
@app.route("/jara/client/<jara_client>/analyse_interface/<interface>")
def analyse_interface(jara_client,interface):
    socketio.emit('analyse_interface',{'interface':interface},room=jara_client)
    return redirect(url_for("jara_clients_display"))
@socketio.on('connect')
def handle_connect():
    print(f'Client connected: {request.sid}')
@socketio.on('python_client')
def python_client(data):
    global jara_clients
    jara_clients[request.sid] = {"files":data["files"],"interfaces":data["interfaces"]}
    print(f'Python client registered: {request.sid}')
    messages.append(f'Python client registered: {request.sid}')
@socketio.on('network_traffic')
def monitor_agent(data):
    global jara_clients
    jara_clients[request.sid]["traffic"] = data
    # url = f'http://localhost:5000/jara/client/{request.sid}/network_stats' 
    # headers = {
    #     'Content-Type': 'application/json' 
    # }
    # try:
    #     response = requests.post(url, json=data,headers=headers)
    #     if response.status_code == 200:
    #         print("Data successfully posted.")
    #     else:
    #         print(f"Failed to post data. Status code: {response.status_code}, Response: {response.text}")
    # except requests.exceptions.RequestException as e:
    #     print(f"An error occurred while trying to post data: {e}")


@socketio.on('disconnect')
def handle_disconnect():
    if request.sid in jara_clients:
        jara_clients.pop(request.sid,None)
        print(f'JARA client disconnected: {request.sid}')
@socketio.on('client_message')
def handle_client_message(data):
    print(f'Received message from client: {data["data"]}')
    messages.append(f'Received message from client: {data["data"]}')

###########################################################################################


#################################SYSTEM CONTROL##############################################
@app.route("/system/reboot")
@login_required
def system_reboot():
    try:
        subprocess.run(['sudo', 'reboot'] , check=True)
    except subprocess.CalledProcessError as e:
        return str(e)
    return "Reboot"
@app.route("/system/shutdown")
@login_required
def system_shutdown():
    try:
        subprocess.run(['sudo', 'shutdown'] , check=True)
    except subprocess.CalledProcessError as e:
        return str(e)
    return "Shutting down"
###########################################WAZUH IFRAME##############################
@app.route("/wazuh")
@login_required
def wazuh():
    return render_template("wazuh.html")
#############################################################################################
app.register_blueprint(wifi_signal_blueprint)
def main():
    # log_thread = LogThread()
    # log_thread.start()
    parser = argparse.ArgumentParser(
        description=(
            "A fully functional terminal in your browser. "
            "https://github.com/cs01/pyxterm.js"
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-p", "--port", default=5000, help="port to run server on", type=int
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="host to run server on (use 0.0.0.0 to allow access from other hosts)",
    )
    parser.add_argument("--debug", action="store_true", help="debug the server")
    parser.add_argument("--version", action="store_true", help="print version and exit")
    parser.add_argument(
        "--command", default="bash", help="Command to run in the terminal"
    )
    parser.add_argument(
        "--cmd-args",
        default="",
        help="arguments to pass to command (i.e. --cmd-args='arg1 arg2 --flag')",
    )
    args = parser.parse_args()
    app.config["cmd"] = [args.command] + shlex.split(args.cmd_args)
    socketio.run(app, debug=True, host="0.0.0.0")
if __name__ == "__main__":
    main()


