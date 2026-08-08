from flask import Flask, render_template, request, send_file
from services.generator_service import generate_and_analyze
from services.analysis_service import analyze_and_save
from services.history_service import load_history
from services.dashboard_service import load_dashboard
from flask import jsonify

from database.db import (
    get_export_data,
    get_dashboard_data,
)
from services.security_event_service import (
    get_recent_events,
    get_event_counts_by_severity,
)
from services.security_event_service import (
    get_recent_events,
    get_event_counts_by_severity,
)

from services.export_service import export_report

app = Flask(__name__)
@app.route("/analyze", methods=["GET"])
def analyze_page():
	return render_template("analyze.html")
	
@app.route("/analyze", methods=["POST"])
def analyze_password():

    password = request.form.get(
        "password",
        "",
    )

    email = request.form.get(
        "email",
        "",
    ).strip()

    hibp_api_key = request.form.get(
        "hibp_api_key",
        "",
    ).strip()

    report = analyze_and_save(
        password=password,
        email=email or None,
        hibp_api_key=hibp_api_key or None,
    )

    return render_template(
        "analyze.html",
        report=report,
    )

@app.route("/generator", methods=["GET"])
def generator():

    return render_template("generator.html")


@app.route("/generator", methods=["POST"])
def generate_password_page():

    length = int(request.form.get("length", 16))

    uppercase = request.form.get("uppercase") == "on"
    lowercase = request.form.get("lowercase") == "on"
    digits = request.form.get("digits") == "on"
    symbols = request.form.get("symbols") == "on"

    exclude_ambiguous = (
        request.form.get("exclude_ambiguous") == "on"
    )

    result = generate_and_analyze(
        length=length,
        uppercase=uppercase,
        lowercase=lowercase,
        digits=digits,
        symbols=symbols,
        exclude_ambiguous=exclude_ambiguous,
    )

    return render_template(
        "generator.html",
        generated=result["password"],
        report=result["report"],
    )
    
@app.route("/security-events")
def security_events():

    events = get_recent_events(50)
    counts = get_event_counts_by_severity()

    return render_template(
        "security_events.html",
        events=events,
        counts=counts,
    )
    
@app.route("/history")
def history():
	analyses = load_history()
	return render_template(
	"history.html",
	analyses=analyses)
	
@app.route("/")
def home():
    dashboard = load_dashboard()

    return render_template(
        "dashboard.html",
        stats=dashboard["stats"],
        recent=dashboard["recent"],
        status=dashboard["status"],
        entropy=dashboard["entropy"],
    )
	
@app.route("/dashboard")
def dashboard():
    data = load_dashboard()

    return render_template(
        "dashboard.html",
        stats=data["stats"],
        recent=data["recent"],
        status=data["status"],
        entropy=data["entropy"],
    )
	
@app.route("/security-events/data")
def security_events_data():

    events = get_recent_events(50)
    counts = get_event_counts_by_severity()

    return jsonify({
        "events": events,
        "counts": counts,
    })
    
    
@app.route("/export/csv")
def export_csv():

    dashboard_data = load_dashboard()

    report = export_report(
        "csv",
        dashboard_data["recent"],
        dashboard_data["stats"],
    )

    return send_file(report, as_attachment=True)


@app.route("/export/json")
def export_json():

    dashboard_data = load_dashboard()

    report = export_report(
        "json",
        dashboard_data["recent"],
        dashboard_data["stats"],
    )

    return send_file(report, as_attachment=True)


@app.route("/export/pdf")
def export_pdf():

    dashboard_data = load_dashboard()

    report = export_report(
        "pdf",
        dashboard_data["recent"],
        dashboard_data["stats"],
    )

    return send_file(report, as_attachment=True)

if __name__ == "__main__":
	app.run(debug=True)
