import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, render_template, request, jsonify
import tempfile

from modules.email_parser    import parse_eml
from modules.header_analyzer import analyze_headers
from modules.url_extractor   import analyze_urls
from modules.nlp_scorer      import score_body
from modules.verdict_engine  import calculate_verdict

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/analyze", methods=["POST"])
def analyze():
    if "email_file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["email_file"]
    if not file.filename.endswith(".eml"):
        return jsonify({"error": "Please upload a .eml file"}), 400

    # Save to temp file
    with tempfile.NamedTemporaryFile(delete=False, suffix=".eml") as tmp:
        file.save(tmp.name)
        tmp_path = tmp.name

    parsed  = parse_eml(tmp_path)
    headers = analyze_headers(parsed)
    urls    = analyze_urls(parsed)
    nlp     = score_body(parsed)
    report  = calculate_verdict(headers, urls, nlp)
    os.unlink(tmp_path)

    return jsonify({
        "email": {
            "from":    parsed["from"],
            "to":      parsed["to"],
            "subject": parsed["subject"],
            "urls":    parsed["urls"]
        },
        "report": report
    })

if __name__ == "__main__":
    app.run(debug=True)