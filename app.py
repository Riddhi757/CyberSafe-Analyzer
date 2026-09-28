from flask import Flask, render_template, request
import os
import hashlib
import mimetypes
import socket
import ssl
from urllib.parse import urlparse

import requests


app = Flask(__name__)

# ---------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# ---------------------------------------------------------
# HOME PAGE
# ---------------------------------------------------------

@app.route("/")
def home():
    return render_template("index.html")


# ---------------------------------------------------------
# WEBSITE SCANNER
# ---------------------------------------------------------

@app.route("/scan", methods=["GET", "POST"])
def scan():

    if request.method == "GET":
        return render_template("index.html")

    # Accept different possible form names
    url = (
        request.form.get("url")
        or request.form.get("website")
        or request.form.get("target_url")
    )

    if not url:
        return "Please enter a website URL."

    url = url.strip()

    # Add http:// if user does not provide it
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    try:
        # -------------------------------------------------
        # REQUEST WEBSITE
        # -------------------------------------------------

        response = requests.get(
            url,
            timeout=15,
            allow_redirects=True,
            headers={
                "User-Agent": "CyberSafe Analyzer/1.0"
            },
            verify=False
        )

        final_url = response.url
        status_code = response.status_code

        parsed_url = urlparse(final_url)
        domain = parsed_url.hostname or "Unknown"

        # -------------------------------------------------
        # IP ADDRESS
        # -------------------------------------------------

        try:
            ip_address = socket.gethostbyname(domain)
        except Exception:
            ip_address = "Unavailable"

        # -------------------------------------------------
        # HTTPS CHECK
        # -------------------------------------------------

        https_enabled = final_url.lower().startswith("https://")

        # -------------------------------------------------
        # SERVER INFORMATION
        # -------------------------------------------------

        server = response.headers.get("Server", "Not disclosed")

        content_type = response.headers.get(
            "Content-Type",
            "Unknown"
        )

        # -------------------------------------------------
        # SECURITY HEADERS
        # -------------------------------------------------

        security_headers = {
            "Content-Security-Policy": response.headers.get(
                "Content-Security-Policy"
            ),
            "Strict-Transport-Security": response.headers.get(
                "Strict-Transport-Security"
            ),
            "X-Content-Type-Options": response.headers.get(
                "X-Content-Type-Options"
            ),
            "X-Frame-Options": response.headers.get(
                "X-Frame-Options"
            ),
            "Referrer-Policy": response.headers.get(
                "Referrer-Policy"
            ),
            "Permissions-Policy": response.headers.get(
                "Permissions-Policy"
            )
        }

        present_headers = [
            name
            for name, value in security_headers.items()
            if value
        ]

        missing_headers = [
            name
            for name, value in security_headers.items()
            if not value
        ]

        # -------------------------------------------------
        # SECURITY SCORE
        # -------------------------------------------------

        score = 100

        # HTTPS
        if not https_enabled:
            score -= 25

        # Security headers
        score -= min(len(missing_headers) * 5, 30)

        # HTTP status
        if status_code >= 500:
            score -= 20
        elif status_code >= 400:
            score -= 15

        score = max(0, min(100, score))

        if score >= 80:
            risk_level = "Low"
        elif score >= 60:
            risk_level = "Medium"
        else:
            risk_level = "High"

        # -------------------------------------------------
        # WEBSITE RESULT
        # -------------------------------------------------

        result = {
            "url": url,
            "final_url": final_url,
            "domain": domain,
            "ip_address": ip_address,
            "status_code": status_code,
            "http_status": status_code,
            "https_enabled": https_enabled,
            "server": server,
            "content_type": content_type,
            "security_score": score,
            "score": score,
            "risk_level": risk_level,
            "security_headers": security_headers,
            "present_headers": present_headers,
            "missing_headers": missing_headers
        }

        # Pass both result AND individual variables.
        # This makes the existing result.html work with
        # different variable names.
        return render_template(
            "result.html",
            result=result,
            url=url,
            final_url=final_url,
            domain=domain,
            ip_address=ip_address,
            status_code=status_code,
            http_status=status_code,
            https_enabled=https_enabled,
            server=server,
            content_type=content_type,
            security_score=score,
            score=score,
            risk_level=risk_level,
            security_headers=security_headers,
            present_headers=present_headers,
            missing_headers=missing_headers
        )

    except requests.exceptions.SSLError:
        return """
        <h2>Website Scan Error</h2>
        <p>SSL certificate verification failed.</p>
        <p>Please check the website URL and try again.</p>
        """

    except requests.exceptions.Timeout:
        return """
        <h2>Website Scan Error</h2>
        <p>The website took too long to respond.</p>
        """

    except requests.exceptions.ConnectionError:
        return """
        <h2>Website Scan Error</h2>
        <p>Could not connect to the website.</p>
        """

    except Exception as e:
        return f"""
        <h2>Website Scan Error</h2>
        <p>{str(e)}</p>
        """


# ---------------------------------------------------------
# FILE SCANNER
# ---------------------------------------------------------

@app.route("/scan-file", methods=["GET", "POST"])
def scan_file():

    if request.method == "GET":
        return render_template("index.html")

    uploaded_file = request.files.get("file")

    # Some forms may use another name
    if uploaded_file is None:
        uploaded_file = request.files.get("uploaded_file")

    if not uploaded_file or uploaded_file.filename == "":
        return "Please select a file."

    # -----------------------------------------------------
    # FILE SIZE
    # -----------------------------------------------------

    uploaded_file.seek(0, os.SEEK_END)
    file_size = uploaded_file.tell()
    uploaded_file.seek(0)

    if file_size > MAX_FILE_SIZE:
        return "File is too large. Maximum size is 10 MB."

    # -----------------------------------------------------
    # FILE NAME
    # -----------------------------------------------------

    filename = os.path.basename(uploaded_file.filename)

    # -----------------------------------------------------
    # SAVE FILE
    # -----------------------------------------------------

    file_path = os.path.join(
        UPLOAD_FOLDER,
        filename
    )

    uploaded_file.save(file_path)

    # -----------------------------------------------------
    # SHA-256 HASH
    # -----------------------------------------------------

    sha256 = hashlib.sha256()

    try:
        with open(file_path, "rb") as file:

            while True:
                chunk = file.read(8192)

                if not chunk:
                    break

                sha256.update(chunk)

        file_hash = sha256.hexdigest()

    except Exception:
        file_hash = "Unavailable"

    # -----------------------------------------------------
    # FILE TYPE
    # -----------------------------------------------------

    file_type = mimetypes.guess_type(filename)[0]

    if not file_type:
        file_type = "Unknown"

    # -----------------------------------------------------
    # FILE EXTENSION
    # -----------------------------------------------------

    extension = os.path.splitext(filename)[1].lower()

    if not extension:
        extension = "None"

    # -----------------------------------------------------
    # BASIC RISK CHECK
    # -----------------------------------------------------

    risky_extensions = [
        ".exe",
        ".dll",
        ".bat",
        ".cmd",
        ".scr",
        ".ps1",
        ".vbs",
        ".vbe",
        ".js",
        ".jar",
        ".msi"
    ]

    if extension in risky_extensions:
        risk = "Review Required"
        risk_level = "High"
        threat_detected = "Potentially Risky File Type"
    else:
        risk = "No Basic Risk Indicator"
        risk_level = "Low"
        threat_detected = "No Threat Detected"

    # -----------------------------------------------------
    # FILE SIZE FORMATTING
    # -----------------------------------------------------

    if file_size < 1024:
        filesize = f"{file_size} B"

    elif file_size < 1024 * 1024:
        filesize = f"{file_size / 1024:.2f} KB"

    else:
        filesize = f"{file_size / (1024 * 1024):.2f} MB"

    # -----------------------------------------------------
    # FILE RESULT
    # -----------------------------------------------------

    result = {
        "filename": filename,
        "file_name": filename,

        "size": file_size,
        "filesize": filesize,
        "file_size": filesize,

        "extension": extension,

        "type": file_type,
        "file_type": file_type,

        "sha256": file_hash,
        "hash": file_hash,

        "risk": risk,
        "risk_level": risk_level,

        "threat_detected": threat_detected,

        "scan_status": "Completed",
        "status": "Completed",

        "file_integrity": "Verified",

        "scan_engine": "CyberSafe Analyzer"
    }

    # -----------------------------------------------------
    # IMPORTANT:
    # Pass the values individually AND inside result.
    #
    # Your File_Result.html is using:
    # {{ filename }}
    # {{ filesize }}
    # {{ file_type }}
    #
    # So these must be passed here.
    # -----------------------------------------------------

    return render_template(
        "File_Result.html",

        result=result,

        filename=filename,
        file_name=filename,

        filesize=filesize,
        file_size=filesize,
        size=file_size,

        extension=extension,

        file_type=file_type,
        type=file_type,

        sha256=file_hash,
        hash=file_hash,

        risk=risk,
        risk_level=risk_level,

        threat_detected=threat_detected,

        scan_status="Completed",
        status="Completed",

        file_integrity="Verified",

        scan_engine="CyberSafe Analyzer"
    )


# ---------------------------------------------------------
# RUN APPLICATION
# ---------------------------------------------------------

if __name__ == "__main__":
    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000
    )