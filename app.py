from flask_wtf.csrf import CSRFProtect
from datetime import datetime
import hashlib
import os
import re
import uuid

from dotenv import load_dotenv
from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
import requests
from werkzeug.utils import secure_filename


# =========================================================
# LOAD ENVIRONMENT VARIABLES
# =========================================================

load_dotenv()

app = Flask(__name__)

app.secret_key = os.getenv("FLASK_SECRET_KEY")

if not app.secret_key:
    raise RuntimeError("FLASK_SECRET_KEY is not set")

VT_API_KEY = os.getenv("VT_API_KEY", "")

csrf = CSRFProtect(app)


if not VT_API_KEY:
    print("WARNING: VT_API_KEY is not set in .env file!")


# =========================================================
# APP CONFIGURATION
# =========================================================

app.config["UPLOAD_FOLDER"] = "uploads"

# 650 MB maximum upload
app.config["MAX_CONTENT_LENGTH"] = 650 * 1024 * 1024

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)


# =========================================================
# VIRUSTOTAL
# =========================================================

def check_virustotal(file_path):

    sha256_hash = hashlib.sha256()

    try:

        file_size = os.path.getsize(file_path)

        with open(file_path, "rb") as f:

            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)

        file_hash = sha256_hash.hexdigest()

    except Exception as e:

        return {
            "status": "error",
            "message": str(e),
            "hash": "",
            "malicious": 0
        }


    if not VT_API_KEY:

        return {
            "status": "error",
            "message": "VT_API_KEY is missing",
            "hash": file_hash,
            "malicious": 0
        }


    headers = {
        "x-apikey": VT_API_KEY
    }

    file_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"


    try:

        response = requests.get(
            file_url,
            headers=headers,
            timeout=10
        )


        # -------------------------------------------------
        # FILE ALREADY EXISTS
        # -------------------------------------------------

        if response.status_code == 200:

            result = response.json()

            stats = (
                result
                .get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
            )

            malicious_count = stats.get("malicious", 0)

            return {
                "status": "success",
                "malicious": malicious_count,
                "hash": file_hash
            }


        # -------------------------------------------------
        # FILE NOT FOUND
        # -------------------------------------------------

        elif response.status_code == 404:

            # VirusTotal requires upload URL for files
            # larger than 32 MB.

            if file_size > 32 * 1024 * 1024:

                url_resp = requests.get(
                    "https://www.virustotal.com/api/v3/files/upload_url",
                    headers=headers,
                    timeout=10
                )

                if url_resp.status_code == 200:

                    upload_url = url_resp.json().get("data")

                else:

                    return {
                        "status": "error",
                        "message": "Could not retrieve VirusTotal large file upload URL.",
                        "hash": file_hash,
                        "malicious": 0
                    }

            else:

                upload_url = (
                    "https://www.virustotal.com/api/v3/files"
                )


            # -------------------------------------------------
            # UPLOAD FILE
            # -------------------------------------------------

            with open(file_path, "rb") as file_to_upload:

                files = {
                    "file": (
                        os.path.basename(file_path),
                        file_to_upload
                    )
                }

                upload_response = requests.post(
                    upload_url,
                    headers=headers,
                    files=files,
                    timeout=60
                )


            if upload_response.status_code in [200, 201]:

                return {
                    "status": "pending",
                    "message": "File submitted to VirusTotal. Analysis in progress.",
                    "hash": file_hash,
                    "malicious": 0
                }

            else:

                return {
                    "status": "not_found",
                    "message": "File upload failed.",
                    "hash": file_hash,
                    "malicious": 0
                }


        # -------------------------------------------------
        # OTHER API ERROR
        # -------------------------------------------------

        else:

            return {
                "status": "error",
                "message": f"API status {response.status_code}",
                "hash": file_hash,
                "malicious": 0
            }


    except requests.exceptions.Timeout:

        return {
            "status": "timeout",
            "message": "VirusTotal API timed out.",
            "hash": file_hash,
            "malicious": 0
        }


    except requests.exceptions.RequestException:

        return {
            "status": "network_error",
            "message": "Could not connect to VirusTotal servers.",
            "hash": file_hash,
            "malicious": 0
        }


# =========================================================
# SCAN HISTORY
# =========================================================

SCAN_HISTORY = []


# =========================================================
# TRANSLATION HELPER
# =========================================================

def t(lang, en_text, my_text):

    if lang == "my":
        return my_text

    return en_text


# =========================================================
# FILE HEURISTIC ANALYSIS
# =========================================================

def analyze_file_heuristics(filepath, filename):

    score = 0

    checks = {}


    # =====================================================
    # 1. DOUBLE EXTENSION
    # =====================================================

    double_ext_pattern = r"\.[a-zA-Z0-9]+\.[a-zA-Z0-9]+$"

    if re.search(double_ext_pattern, filename):

        en_desc = (
            "Two extensions are used to hide the true file type."
        )

        my_desc = (
            "ဖိုင်အမျိုးအစားအမှန်ကို ဖုံးကွယ်ရန် Extension ၂ ခု သုံးထားသည်။"
        )

        checks["double_ext"] = {
            "title_en": "Double Extension Check",
            "title_my": "Extension နှစ်ခု စစ်ဆေးခြင်း",
            "status": "FAIL",
            "desc_en": en_desc,
            "desc_my": my_desc,
            "score": 30
        }

        score += 30


    else:

        en_desc = (
            "Only a single standard extension is used."
        )

        my_desc = (
            "ပုံမှန် Extension တစ်ခုတည်းသာ သုံးထားသည်။"
        )

        checks["double_ext"] = {
            "title_en": "Double Extension Check",
            "title_my": "Extension နှစ်ခု စစ်ဆေးခြင်း",
            "status": "PASS",
            "desc_en": en_desc,
            "desc_my": my_desc,
            "score": 0
        }


    # =====================================================
    # 2. SUSPICIOUS KEYWORDS
    # =====================================================

    keywords = [
        "crack",
        "patch",
        "free",
        "password",
        "urgent",
        "invoice",
        "hack",
        "bypass",
        "keyex"
    ]

    found_keywords = [
        kw for kw in keywords
        if kw in filename.lower()
    ]


    if found_keywords:

        keyword_text = ", ".join(found_keywords)

        en_desc = (
            f"Suspicious keyword(s) ({keyword_text}) found."
        )

        my_desc = (
            f"မသင်္ကာဖွယ်စကားလုံး ({keyword_text}) ပါဝင်နေသည်။"
        )

        checks["keywords"] = {
            "title_en": "Suspicious Keywords",
            "title_my": "မသင်္ကာဖွယ် စကားလုံးများ",
            "status": "FAIL",
            "desc_en": en_desc,
            "desc_my": my_desc,
            "score": 25
        }

        score += 25


    else:

        en_desc = (
            "No dangerous keywords found."
        )

        my_desc = (
            "အန္တရာယ်ရှိသော အသုံးအနှုန်းများ မတွေ့ရပါ။"
        )

        checks["keywords"] = {
            "title_en": "Suspicious Keywords",
            "title_my": "မသင်္ကာဖွယ် စကားလုံးများ",
            "status": "PASS",
            "desc_en": en_desc,
            "desc_my": my_desc,
            "score": 0
        }


    # =====================================================
    # 3. EXECUTABLE FORMAT
    # =====================================================

    danger_exts = [
        ".exe",
        ".bat",
        ".cmd",
        ".sh",
        ".vbs",
        ".scr",
        ".jar",
        ".msi",
        ".pif"
    ]

    _, ext = os.path.splitext(filename.lower())


    if ext in danger_exts:

        en_desc = (
            f"Directly executable dangerous format ({ext})."
        )

        my_desc = (
            f"တိုက်ရိုက် Run နိုင်သော အန္တရာယ်ရှိနိုင်သည့် format ({ext}) ဖြစ်သည်။"
        )

        checks["extension"] = {
            "title_en": "Executable Threat Check",
            "title_my": "Executable ဖိုင် စစ်ဆေးခြင်း",
            "status": "DANGER",
            "desc_en": en_desc,
            "desc_my": my_desc,
            "score": 35
        }

        score += 35


    else:

        en_desc = (
            "Safe file format."
        )

        my_desc = (
            "လုံခြုံစိတ်ချရသော File Format ဖြစ်သည်။"
        )

        checks["extension"] = {
            "title_en": "Executable Threat Check",
            "title_my": "Executable ဖိုင် စစ်ဆေးခြင်း",
            "status": "PASS",
            "desc_en": en_desc,
            "desc_my": my_desc,
            "score": 0
        }


    # =====================================================
    # 4. FILE INTEGRITY
    # =====================================================

    try:

        file_size = os.path.getsize(filepath)

    except OSError:

        file_size = 0


    if file_size == 0:

        en_desc = (
            "No data in the file (0-byte file)."
        )

        my_desc = (
            "ဖိုင်ထဲတွင် မည်သည့်ဒေတာမျှ မရှိပါ (0-Byte File)။"
        )

        checks["integrity"] = {
            "title_en": "File Integrity Scan",
            "title_my": "ဖိုင် Integrity စစ်ဆေးခြင်း",
            "status": "FAIL",
            "desc_en": en_desc,
            "desc_my": my_desc,
            "score": 10
        }

        score += 10


    elif file_size < 100:

        en_desc = (
            "File size is unusually small."
        )

        my_desc = (
            "ဖိုင်အရွယ်အစား သာမန်ထက် သေးငယ်လွန်းနေသည်။"
        )

        checks["integrity"] = {
            "title_en": "File Integrity Scan",
            "title_my": "ဖိုင် Integrity စစ်ဆေးခြင်း",
            "status": "SUSPICIOUS",
            "desc_en": en_desc,
            "desc_my": my_desc,
            "score": 5
        }

        score += 5


    else:

        en_desc = (
            f"File size is normal ({file_size} bytes)."
        )

        my_desc = (
            f"ဖိုင်အရွယ်အစား ကောင်းမွန်ပါသည် ({file_size} bytes)။"
        )

        checks["integrity"] = {
            "title_en": "File Integrity Scan",
            "title_my": "ဖိုင် Integrity စစ်ဆေးခြင်း",
            "status": "PASS",
            "desc_en": en_desc,
            "desc_my": my_desc,
            "score": 0
        }


    # =====================================================
    # VIRUSTOTAL
    # =====================================================

    vt_result = check_virustotal(filepath)

    file_hash = vt_result.get("hash", "")

    vt_malicious = vt_result.get(
        "malicious",
        0
    )

    vt_status = vt_result.get("status")


    # -----------------------------------------------------
    # VT TIMEOUT
    # -----------------------------------------------------

    if vt_status == "timeout":

        en_desc = (
            "VirusTotal response timed out. "
            "Relying on local heuristic analysis."
        )

        my_desc = (
            "VirusTotal API သို့ ဆက်သွယ်မှု ကြာမြင့်နေ၍ "
            "Local Static Heuristic Analysis ကိုသာ အသုံးပြုထားသည်။"
        )

        checks["virustotal"] = {
            "title_en": "VirusTotal Intelligence",
            "title_my": "VirusTotal Intelligence",
            "status": "SUSPICIOUS",
            "desc_en": en_desc,
            "desc_my": my_desc,
            "score": 0
        }


    # -----------------------------------------------------
    # VT NETWORK ERROR
    # -----------------------------------------------------

    elif vt_status == "network_error":

        en_desc = (
            "Network error occurred while contacting VirusTotal."
        )

        my_desc = (
            "VirusTotal သို့ ချိတ်ဆက်ရာတွင် Network အမှားအယွင်း ရှိနေသည်။"
        )

        checks["virustotal"] = {
            "title_en": "VirusTotal Intelligence",
            "title_my": "VirusTotal Intelligence",
            "status": "SUSPICIOUS",
            "desc_en": en_desc,
            "desc_my": my_desc,
            "score": 0
        }


    # -----------------------------------------------------
    # VT PENDING
    # -----------------------------------------------------

    elif vt_status == "pending":

        en_desc = (
            "File was submitted to VirusTotal, "
            "but the analysis is still pending. "
            "No final VirusTotal detection result is available yet."
        )

        my_desc = (
            "ဖိုင်ကို VirusTotal သို့ ပေးပို့ထားသော်လည်း "
            "စစ်ဆေးမှုမှာ လုပ်ဆောင်နေဆဲဖြစ်ပါသည်။ "
            "VirusTotal ၏ နောက်ဆုံး Detection Result မရရှိသေးပါ။"
        )

        checks["virustotal"] = {
            "title_en": "VirusTotal Intelligence",
            "title_my": "VirusTotal Intelligence",
            "status": "SUSPICIOUS",
            "desc_en": en_desc,
            "desc_my": my_desc,
            "score": 0
        }


    # -----------------------------------------------------
    # VT DETECTION
    # -----------------------------------------------------

    elif vt_malicious > 0:

        vt_score = min(
            100,
            vt_malicious * 10
        )

        score += vt_score


        en_desc = (
            f"Malware detected by VirusTotal "
            f"({vt_malicious} detections)."
        )

        my_desc = (
            f"VirusTotal မှ မာလ်ဝဲလ် "
            f"({vt_malicious} detections) တွေ့ရှိထားသည်။"
        )

        checks["virustotal"] = {
            "title_en": "VirusTotal Intelligence",
            "title_my": "VirusTotal Intelligence",
            "status": "FAIL",
            "desc_en": en_desc,
            "desc_my": my_desc,
            "score": vt_score
        }


    # -----------------------------------------------------
    # VT CLEAN
    # -----------------------------------------------------

    else:

        en_desc = (
            "No threats found on VirusTotal."
        )

        my_desc = (
            "VirusTotal တွင် အန္တရာယ်တစ်စုံတစ်ရာ မတွေ့ရပါ။"
        )

        checks["virustotal"] = {
            "title_en": "VirusTotal Intelligence",
            "title_my": "VirusTotal Intelligence",
            "status": "PASS",
            "desc_en": en_desc,
            "desc_my": my_desc,
            "score": 0
        }


    # =====================================================
    # FINAL SCORE
    # =====================================================

    score = min(
        score,
        100
    )


    # =====================================================
    # FINAL STATUS + ADVICE
    # =====================================================

    if score >= 70:

        status = "Danger"

        advice_en = (
            "WARNING: Do NOT open this file! "
            "High probability of malware or virus."
        )

        advice_my = (
            "သတိပေးချက် - ဤဖိုင်ကို လုံးဝမဖွင့်ပါနှင့်! "
            "မာလ်ဝဲလ် သို့မဟုတ် ဗိုင်းရပ်စ် ဖြစ်နိုင်ခြေ အလွန်မြင့်မားသည်။"
        )


    elif score >= 30:

        status = "Caution"

        advice_en = (
            "CAUTION: Do not open if you don't trust the source. "
            "Further inspection is needed."
        )

        advice_my = (
            "သတိပြုရန် - ဖိုင်ရင်းမြစ်ကို သေချာမသိပါက မဖွင့်သင့်ပါ။ "
            "ထပ်မံစစ်ဆေးရန် လိုအပ်သည်။"
        )


    else:

        status = "Safe"


        if vt_status == "pending":

            advice_en = (
                "Static Heuristic Analysis shows no threat, "
                "but VirusTotal analysis is still in progress."
            )

            advice_my = (
                "Static Heuristic Analysis အရ စိတ်ချရသော်လည်း "
                "VirusTotal စစ်ဆေးမှု မပြီးဆုံးသေးပါ။"
            )


        elif vt_status in [
            "timeout",
            "network_error"
        ]:

            advice_en = (
                "Static Heuristic Analysis shows no threat. "
                "VirusTotal check could not be completed."
            )

            advice_my = (
                "Static Heuristic Analysis အရ စိတ်ချရသော်လည်း "
                "VirusTotal စစ်ဆေးမှု မပြီးမြောက်ခဲ့ပါ။"
            )


        else:

            advice_en = (
                "SAFE: The file appears safe according to "
                "Static Heuristic Analysis and VirusTotal."
            )

            advice_my = (
                "စိတ်ချရပါသည် - Static Heuristic Analysis နှင့် "
                "VirusTotal စစ်ဆေးချက်များအရ လုံခြုံမှုရှိပါသည်။"
            )


    # =====================================================
    # RETURN RESULT
    # =====================================================

    return {

        "score": score,

        "status": status,

        "checks": checks,

        "hash": file_hash,

        "size": (
            f"{round(file_size / 1024, 2)} KB"
            if file_size < 1024 * 1024
            else f"{round(file_size / (1024 * 1024), 2)} MB"
        ),

        "advice_en": advice_en,

        "advice_my": advice_my,

        "vt_status": vt_status,

        "vt_malicious": vt_malicious
    }


# =========================================================
# VIRUSTOTAL BACKGROUND STATUS API
# =========================================================

@app.route("/api/vt_status/<file_hash>")
def get_vt_status(file_hash):

    if not VT_API_KEY:

        return jsonify({
            "status": "error",
            "message": "Missing VT_API_KEY"
        })


    headers = {
        "x-apikey": VT_API_KEY
    }

    file_url = (
        f"https://www.virustotal.com/api/v3/files/{file_hash}"
    )


    try:

        res = requests.get(
            file_url,
            headers=headers,
            timeout=5
        )


        if res.status_code == 200:

            stats = (
                res
                .json()
                .get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
            )

            return jsonify({

                "status": "completed",

                "malicious": stats.get(
                    "malicious",
                    0
                )
            })


        else:

            return jsonify({
                "status": "pending"
            })


    except requests.exceptions.RequestException:

        return jsonify({
            "status": "error",
            "message": "VirusTotal connection error."
        })


# =========================================================
# LANGUAGE ROUTE
# =========================================================

@app.route("/set_lang/<lang>")
def set_lang(lang):

    if lang in ["en", "my"]:

        session["lang"] = lang

    # IMPORTANT:
    # This route is no longer used by the language button.
    # It is kept only for compatibility.

    return redirect(
        request.referrer or url_for("index")
    )


# =========================================================
# MAIN PAGE
# =========================================================

@app.route("/", methods=["GET", "POST"])
def index():

    current_lang = session.get(
        "lang",
        "en"
    )

    analysis_result = None

    scanned_file_name = None


    # =====================================================
    # FILE UPLOAD
    # =====================================================

    if request.method == "POST":

        if "file" not in request.files:

            flash("No file part")

            return redirect(request.url)


        file = request.files["file"]


        if file.filename == "":

            flash("No selected file")

            return redirect(request.url)


        filename = secure_filename(
            file.filename
        )


        if file:

            unique_filename = (
                f"{uuid.uuid4().hex}_{filename}"
            )

            filepath = os.path.join(
                app.config["UPLOAD_FOLDER"],
                unique_filename
            )


            try:

                file.save(filepath)


                analysis_result = (
                    analyze_file_heuristics(
                        filepath,
                        filename
                    )
                )


                scanned_file_name = filename


                new_record = {

                    "filename": filename,

                    "hash": (
                        analysis_result["hash"][:15] + "..."
                        if analysis_result["hash"]
                        else "N/A"
                    ),

                    "score": analysis_result["score"],

                    "status": analysis_result["status"],

                    "date": datetime.now().strftime(
                        "%Y-%m-%d %H:%M"
                    ),

                    "size": analysis_result["size"]
                }


                SCAN_HISTORY.insert(
                    0,
                    new_record
                )


            finally:

                if os.path.exists(filepath):

                    os.remove(filepath)


    # =====================================================
    # DASHBOARD COUNTS
    # =====================================================

    total_scanned = len(
        SCAN_HISTORY
    )

    danger_count = sum(
        1
        for item in SCAN_HISTORY
        if item["status"] == "Danger"
    )

    caution_count = sum(
        1
        for item in SCAN_HISTORY
        if item["status"] == "Caution"
    )

    safe_count = sum(
        1
        for item in SCAN_HISTORY
        if item["status"] == "Safe"
    )


    return render_template(

        "index.html",

        history=SCAN_HISTORY,

        total=total_scanned,

        danger=danger_count,

        caution=caution_count,

        safe=safe_count,

        result=analysis_result,

        filename=scanned_file_name,

        current_lang=current_lang
    )


# =========================================================
# HISTORY
# =========================================================

@app.route("/history")
def history():

    current_lang = session.get(
        "lang",
        "en"
    )


    total_scanned = len(
        SCAN_HISTORY
    )


    danger_count = sum(
        1
        for item in SCAN_HISTORY
        if item["status"] == "Danger"
    )


    caution_count = sum(
        1
        for item in SCAN_HISTORY
        if item["status"] == "Caution"
    )


    safe_count = sum(
        1
        for item in SCAN_HISTORY
        if item["status"] == "Safe"
    )


    return render_template(

        "history.html",

        history=SCAN_HISTORY,

        total=total_scanned,

        danger=danger_count,

        caution=caution_count,

        safe=safe_count,

        current_lang=current_lang
    )


# =========================================================
# RUN
# =========================================================

if __name__ == "__main__":

    app.run(
        debug=True,
        port=5001
    )