# web_app.py
import os
import tempfile
from flask import Flask, request, render_template, redirect, url_for, flash
from pcap_agent import analyze_pcap_with_llm  # re-use your existing logic

app = Flask(__name__)
app.secret_key = "change-me-in-real-life"  # needed for flash messages


@app.route("/", methods=["GET", "POST"])
def upload():
    if request.method == "POST":
        if "pcap_file" not in request.files:
            flash("No file part in the request.")
            return redirect(request.url)

        file = request.files["pcap_file"]
        if file.filename == "":
            flash("No file selected.")
            return redirect(request.url)

        # Optional: restrict file types
        if not (file.filename.endswith(".pcap") or file.filename.endswith(".pcapng")):
            flash("Please upload a .pcap or .pcapng file.")
            return redirect(request.url)

        # Save to a temp file
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
            file.save(tmp.name)
            temp_path = tmp.name

        # Run your agent
        try:
            analysis_text = analyze_pcap_with_llm(temp_path)	
            from datetime import datetime
            import json
            from pathlib import Path

            def save_analysis(original_filename: str, analysis_text: str):
                out_dir = Path("analyses")
                out_dir.mkdir(exist_ok=True)

                record = {
                    "timestamp_utc": datetime.utcnow().isoformat() + "Z",
                    "original_filename": original_filename,
                    "analysis": analysis_text,
                    # later you can add: "summary": summary_dict, "flow_stats": flow_stats, ...
                }

                # simple id based on timestamp
                fname = datetime.utcnow().strftime("%Y%m%d-%H%M%S") + ".json"
                (out_dir / fname).write_text(json.dumps(record, indent=2))


            # inside your POST handler, after analysis_text = ...
            save_analysis(file.filename, analysis_text)

        finally:
            # Clean up temp file
            try:
                os.remove(temp_path)
            except OSError:
                pass

        return render_template("result.html",
                               filename=file.filename,
                               analysis=analysis_text)

    # GET
    return render_template("upload.html")


if __name__ == "__main__":
    # Run the dev server
    app.run(host="0.0.0.0", port=5050, debug=True)

