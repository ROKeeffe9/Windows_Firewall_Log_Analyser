import os
from flask import Flask, render_template, request, session
from flask_wtf.csrf import CSRFProtect 
import uuid
from logic import file_to_list, pop_filter_data, filter_logs, add_detail, pop_map, get_stats, get_time_data, get_filter_config, configure_logs, validate

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# CSRF Protection
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-key")

csrf = CSRFProtect(app)

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Temporary storage for uploaded logs -> uses session key
log_store = {}

@app.route("/", methods=["GET", "POST"])
def upload():


    # --------- GET --------- 
    
    # Show upload page
    if request.method == "GET":
        return render_template("upload.html")


    # --------- POST ---------

    file_doc = request.files.get("logfile")

    if file_doc and file_doc.filename != "":
        logs = file_to_list(file_doc)

        if not logs:
            return render_template("upload.html", error_message="Failed to upload file")

        # Store metadata for header bar -> not to be overwritten when filtering
        session["file_name"] = file_doc.filename
        session["total_logs"] = len(logs)

        # Store logs using a session ID -> avoids storing large data sets in session cookies
        log_id = str(uuid.uuid4())
        log_store[log_id] = logs
        session["log_id"] = log_id

    else:
        log_id = session.get("log_id")
        logs = log_store.get(log_id)

    # General error handling
    if not logs:
        return render_template("upload.html", error_message="Failed to upload file")

    # Error handling for issue with value(s) in logs + generate diagnostic message
    error_message = validate(logs)
    if error_message:
        return render_template("upload.html", error_message=error_message)


    # --------- Process ---------

    # Enrich logs with detail
    enriched_logs = add_detail(logs)

    # Restructure logs -> controls what fields are included in HTML table
    configured_logs = configure_logs(enriched_logs)

    # Get headers -> for use in headers row of table
    headers = configured_logs[0].keys() if configured_logs else []


    # --------- Filter ---------

    filter_config = get_filter_config(logs)

    # Remember filters when changing page
    if request.form.get("page"):
        filter_inputs = session.get("filters", {})
    else:
        filter_inputs = pop_filter_data(request.form, filter_config)
    session["filters"] = filter_inputs

    filtered_logs = filter_logs(configured_logs, filter_inputs)


    # --------- Pagination ---------
    
    # Splits log data into pages -> smoother web page (less buffering/lag)
   
    PAGE_SIZE = 100

    page = request.form.get("page", 1)
    try:
        page = int(page)
    except (ValueError, TypeError):
        page = 1

    total_logs = len(filtered_logs)
    total_pages = max(1, (total_logs + PAGE_SIZE - 1) // PAGE_SIZE)

    page = max(1, min(page, total_pages))

    start = (page - 1) * PAGE_SIZE
    end = start + PAGE_SIZE

    logs_page = filtered_logs[start:end]


    # --------- Stats --------- 
    
    # For data visualisation at top of page
    map_points = pop_map(filtered_logs)
    log_stats = get_stats(filtered_logs)
    time_data = get_time_data(filtered_logs)


    # --------- Render ---------

    return render_template(
        "viewer.html",
        logs=logs_page,
        headers=headers,
        map_points=map_points,
        log_stats=log_stats,
        time_data=time_data,
        filter_config=filter_config,
        current_page=page,
        total_pages=total_pages,
        file_name=session.get("file_name"),
        total_logs=session.get("total_logs")
    )


if __name__ == "__main__":
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug)
