from flask import Flask, render_template, request, redirect, url_for, make_response, jsonify
import logging
import os

import packetAnalyzer
import pap

logging.basicConfig(
    filename="analysis.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

app = Flask(__name__)

current_filter = "ALL"

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# ---------------------------------------------------------
# Routes
# ---------------------------------------------------------
@app.route("/start")
def start_capture():
    packetAnalyzer.start_capture()
    return redirect(url_for("index"))

@app.route("/stop")
def stop_capture():
    packetAnalyzer.stop_capture()
    return redirect(url_for("index"))

@app.route("/")
def index():
    # This renders the dashboard template
    return render_template("index.html")

@app.route("/dns")
def dns_page():
    dns_data = pap.captured_packets
    return render_template("dns.html", dns_data=dns_data)

@app.route("/upload", methods=["GET", "POST"])
def upload():
    if request.method == "POST":
        file = request.files.get("pcapfile")
        if not file or file.filename == "":
            return "No file selected"
        filepath = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(filepath)
        try:
            pap.process_pcap(filepath)
        except Exception as e:
            return f"PCAP processing error: {str(e)}"
        return redirect(url_for("dns_page"))
    return render_template("upload.html")

@app.route("/export_dns")
def export_dns():
    output = [["Source IP", "Destination IP", "Query", "Type", "Resolved IP", "Rcode", "Risk"]]
    for row in pap.captured_packets:
        output.append([
            row.get("src", ""), row.get("dst", ""), row.get("dns_query", ""),
            row.get("dns_type", ""), row.get("dns_ip", ""),
            row.get("dns_rcode", ""), row.get("risk", "")
        ])
    csv_text = "\n".join([",".join(map(str, r)) for r in output])
    response = make_response(csv_text)
    response.headers["Content-Disposition"] = "attachment; filename=dns_report.csv"
    response.headers["Content-Type"] = "text/csv"
    return response

# --- API Endpoints for the Frontend ---

@app.route("/packets")
def get_packets_json():
    # Use the global filter variable
    global current_filter 
    
    packet_list = []
    for p in packetAnalyzer.get_packets():
        is_dns = "DNS" in p.get("summary", "")
        p_type = "DNS" if is_dns else "OTHER"
        
        # Apply the filter logic
        if current_filter == "DNS" and p_type != "DNS":
            continue # Skip this packet if it's not DNS
            
        packet_list.append({
            "src": p.get("src"),
            "dst": p.get("dst"),
            "proto": p.get("proto"),
            "summary": p.get("summary"),
            "details": p.get("details"),
            "type": p_type,
            "domain": p.get("dns_query") if is_dns else ""
        })
    return jsonify(packet_list)

@app.route("/stats")
def get_stats_json():
    # This replaces your old 'stats' function
    return jsonify(packetAnalyzer.get_stats())

@app.route('/set_filter/<filter_type>')
def set_filter(filter_type):
    global current_filter
    current_filter = filter_type
    return jsonify({'status': 'ok'})
# ---------------------------------------------------------
# Run
# ---------------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True)
