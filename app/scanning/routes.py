"""Web routes for file and text scanning."""

from flask import Blueprint, flash, render_template, request

from app.auth.services import get_current_user, role_required
from app.models.user import Role
from app.scanning.extractors import ExtractionError
from app.scanning.scanner import ScanService

scanning_bp = Blueprint("scanning", __name__, url_prefix="/scanning")


@scanning_bp.route("/upload", methods=["GET", "POST"])
@role_required(Role.ADMIN, Role.ANALYST)
def upload():
    """File upload and direct text scanner."""
    user = get_current_user()
    result = None

    if request.method == "POST":
        scan_mode = request.form.get("scan_mode", "file")
        is_simulation = request.form.get("is_simulation") == "on"

        try:
            if scan_mode == "text":
                content = request.form.get("content", "").strip()
                source_name = request.form.get("source_name", "manual_input.txt").strip() or "manual_input.txt"
                if not content:
                    flash("Please provide content to scan.", "warning")
                    return render_template("scanning/upload.html")

                result = ScanService.scan_text(
                    text=content,
                    source_name=source_name,
                    is_simulation=is_simulation,
                    user=user,
                )
            else:
                if "file" not in request.files or not request.files["file"].filename:
                    flash("Please select a file to upload.", "warning")
                    return render_template("scanning/upload.html")

                uploaded_file = request.files["file"]
                result = ScanService.scan_file(
                    file=uploaded_file,
                    is_simulation=is_simulation,
                    user=user,
                )

            flash("Scan completed successfully.", "success")
            return render_template("scanning/result.html", result=result)

        except ExtractionError as e:
            flash(f"Scanning failed security check: {e}", "danger")
        except Exception as e:
            flash(f"An unexpected error occurred during scanning: {e}", "danger")

    return render_template("scanning/upload.html")
