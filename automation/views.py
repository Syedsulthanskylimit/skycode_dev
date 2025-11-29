from datetime import datetime
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
import json
import time
from django.conf import settings
import requests
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.shortcuts import get_object_or_404
from form_generator.models import Case
from form_generator.utils.log_time import log_time
from .tasks import evaluate_all_slas
from .models import *
from custom_components.models import *
from .serializers import SlaSerializer
import logging
import imaplib
import smtplib
import email
from email.mime.text import MIMEText
import os
from io import BytesIO
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from PyPDF2 import PdfMerger
from docx import Document
from PIL import Image
import re
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors


logger = logging.getLogger(__name__)


class SlaAPIView(APIView):
    """
    Handles GET, POST, PUT, DELETE based on method & URL
    """

    def get(self, request, sla_id=None):
        """
        If sla_id is provided: get single SLA
        Else: list all SLAs
        """
        try:
            if sla_id:
                sla = get_object_or_404(SlaConfig, id=sla_id)
                serializer = SlaSerializer(sla)
                return Response(serializer.data, status=status.HTTP_200_OK)
            else:
                slas = SlaConfig.objects.all()
                serializer = SlaSerializer(slas, many=True)
                return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            logger.exception(f"[Error] GET failed: {e}")
            return Response({"error": "GET failed."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def post(self, request):
        """
        Create new SLA
        """
        try:
            serializer = SlaSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.exception(f"[Error] POST failed: {e}")
            return Response({"error": "POST failed."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def put(self, request, sla_id=None):
        """
        Update SLA by ID
        """
        try:
            if not sla_id:
                return Response({"error": "SLA ID is required for update."}, status=status.HTTP_400_BAD_REQUEST)
            sla = get_object_or_404(SlaConfig, id=sla_id)
            serializer = SlaSerializer(sla, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.exception(f"[Error] PUT failed: {e}")
            return Response({"error": "PUT failed."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self, request, sla_id=None):
        """
        Delete SLA by ID
        """
        try:
            if not sla_id:
                return Response({"error": "SLA ID is required for delete."}, status=status.HTTP_400_BAD_REQUEST)
            sla = get_object_or_404(SlaConfig, id=sla_id)
            sla.delete()
            return Response({"message": "SLA deleted successfully."}, status=status.HTTP_204_NO_CONTENT)
        except Exception as e:
            logger.exception(f"[Error] DELETE failed: {e}")
            return Response({"error": "DELETE failed."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class EvaluateSLAAPIView(APIView):
    """
    API endpoint to trigger SLA evaluation synchronously.
    """

    def get(self, request):
        try:
            result = evaluate_all_slas()
            return Response(result, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"status": False, "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class MailAutomationView(APIView):
    """
    Handles automated email fetching, regex-based filtering, PDF generation,
    DMS upload, and optional email forwarding for agents.
    """

    def get(self, request, *args, **kwargs):
        try:
            # Fetch all active agents configured for mail automation
            start_time = time.time()
            mail_agents = Agent.objects.filter(agent_name="Mail2PDF Agent", is_active=True)
            if not mail_agents.exists():
                return Response(
                    {"status": False, "message": "No active Mail Automation agents found."},
                    status=status.HTTP_404_NOT_FOUND
                )
            log_time("Agent filtering",start_time)
            results = []

            for agent in mail_agents:
                start_time = time.time()
                results.append(self._process_agent(agent))
                log_time("Looping mail_agents",start_time)
            
            return Response(
                {"status": True, "message": "Mail automation completed successfully.", "results": results},
                status=status.HTTP_200_OK
            )

        except imaplib.IMAP4.error as e:
            return Response({"status": False, "message": f"IMAP connection failed: {str(e)}"},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except smtplib.SMTPException as e:
            return Response({"status": False, "message": f"SMTP error: {str(e)}"},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            return Response({"status": False, "message": f"Unexpected error: {str(e)}"},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    # -------------------------------------------------------------------------
    # Main Logic
    # -------------------------------------------------------------------------

    def _process_agent(self, agent_instance):
        config = agent_instance.agent_config_schema or {}
        credentials = config.get("mail_credentials", {})
        user_email = credentials.get("mail")
        app_password = credentials.get("app_password")

        if not user_email or not app_password:
            return {"agent_name": agent_instance.agent_name, "status": False, "message": "Missing email credentials."}

        inbox_type = config.get("inbox_type", "all").lower()
        allowed_senders = config.get("allowed_senders", [])
        subject_pattern = config.get("subject_regex")

        start_time = time.time()
        imap_server, smtp_server, smtp_port = self._get_mail_server_config(
            config.get("mail_type", ""), config.get("custom_servers", {})
        )
        log_time("_get_mail_server_config",start_time)


        try:
            start_time = time.time()
            unread_emails = self._fetch_unread_emails(
                imap_server=imap_server,
                email_user=user_email,
                app_password=app_password,
                inbox_type=inbox_type,
                allowed_senders=allowed_senders
            )
            log_time("_fetch_unread_emails",start_time)
            
        except Exception as e:
            return {"agent_name": agent_instance.agent_name, "status": False, "message": f"Failed to fetch emails: {str(e)}"}

        if not subject_pattern:
            return {"agent_name": agent_instance.agent_name, "status": False, "message": "No subject regex defined."}

        regex = re.compile(subject_pattern)
        matched_emails = []

        start_time = time.time()
        for email_item in unread_emails:
            subject = email_item.get("subject", "")
            match = regex.search(subject)
            if match:
                email_item["regex_match_code"] = match.group(0)
                matched_emails.append(email_item)
            else:
                print(f"Skipped email (no regex match): {subject}")
        log_time("matched_emails",start_time)

        if not matched_emails:
            return {"agent_name": agent_instance.agent_name, "status": False, "message": "No regex-matched emails found."}

        # Get organization (via CreateProcess)
        organization_instance = agent_instance.organization
        if not organization_instance:
            return {"agent_name": agent_instance.agent_name, "status": False, "message": "Organization not linked."}

        dms_config = Dms.objects.filter(organization=organization_instance).first()
        if not dms_config:
            return {"agent_name": agent_instance.agent_name, "status": False, "message": "No DMS config found."}

        start_time = time.time()
        self._process_emails_to_dms(matched_emails, dms_config, organization_instance)
        log_time("_process_emails_to_dms",start_time)

        # Optional email forwarding
        if config.get("should_forward") and config.get("forward_to"):
            for mail_item in matched_emails:
                try:
                    start_time = time.time()
                    self._forward_email(
                        smtp_server, smtp_port,
                        sender_email=user_email,
                        app_password=app_password,
                        recipients=config["forward_to"],
                        subject=mail_item["subject"],
                        body=mail_item["body"],
                        attachments=mail_item.get("attachments", []),
                        original_from=mail_item.get("from"),
                        original_date=mail_item.get("date")
                    )
                    log_time("_forward_email",start_time)
                except Exception as forward_err:
                    print(f"Email forwarding failed: {forward_err}")

        return {"agent_name": agent_instance.agent_name, "status": True, "message": "Emails processed successfully.", "email_count": len(matched_emails)}

    # -------------------------------------------------------------------------
    # Utility Methods
    # -------------------------------------------------------------------------

    def _process_emails_to_dms(self, emails, dms_config, organization_instance):
        """Convert emails to PDF, merge attachments, and upload to DMS."""
        dms_json = dms_config.config_details_schema
        dms_json["drive_types"] = dms_config.drive_types

        for email_data in emails:
            # Make a shallow copy to preserve original email data
            email_copy = email_data.copy()
            attachments = email_copy.get("attachments", [])
            unique_code = email_copy.get("regex_match_code")

            start_time = time.time()
            cases = self._get_case_by_code(unique_code, organization_instance) or []
            log_time("_get_case_by_code", start_time)

            try:
                start_time = time.time()
                email_pdf = self._generate_email_pdf(email_copy, attachments)
                log_time("_generate_email_pdf", start_time)

                safe_subject = "".join(
                    [ch for ch in email_copy["subject"] if ch.isalnum() or ch in " _-"]
                )

                # If no matching case found, still upload the email
                if not cases:
                    cases = [None]

                for case in cases:
                    metadata = {
                        "case_id": str(case.id) if case else "",
                        "organization_id": str(organization_instance.id),
                        "data_json": json.dumps({})
                    }
                    dms_json["metadata"] = json.dumps(metadata)

                    files = {"files": (f"{safe_subject}.pdf", email_pdf, "application/pdf")}
                    upload_url = f"{settings.BASE_URL}/custom_components/FileUploadView/"

                    start_time = time.time()
                    response = requests.post(upload_url, data=dms_json, files=files)
                    print(f"[{safe_subject}] FileUploadView response:", response.status_code)
                    log_time("FileUploadView response", start_time)

                    if response.status_code == 200:
                        resp_json = response.json()

                        start_time = time.time()
                        Dms_data.objects.get_or_create(
                            folder_id=resp_json.get("file_id"),
                            filename=resp_json.get("file_name"),
                            dms=dms_config,
                            flow_id=getattr(case, "processId", None),
                            case_id=case,
                            download_link=resp_json.get("download_link"),
                            organization=organization_instance,
                            defaults={"meta_data": dms_json["metadata"]}
                        )
                        log_time("Dms_data create", start_time)
                    else:
                        print(f"[{safe_subject}] Upload failed with status: {response.status_code}")

            except Exception as e:
                print(f"Error uploading PDF for email '{email_copy.get('subject')}': {e}")

    def _get_case_by_code(self, case_code, organization):
        """Find all Case records matching the unique regex code."""
        try:
            if not case_code:
                return []

            matched_cases = []
            cases = Case.objects.filter(organization=organization, parent_case_data__icontains=case_code).exclude(status="Completed")

            for case in cases:
                for field in case.parent_case_data or []:
                    if isinstance(field, dict) and field.get("value") == case_code:
                        matched_cases.append(case)
                        break  # stop inner loop once match found in this case

            return matched_cases

        except Exception as e:
            print(f"Case lookup error for '{case_code}': {e}")
            return []

    def _get_mail_server_config(self, mail_type, custom_servers):
        """Return IMAP/SMTP settings."""
        mapping = {
            "gmail": ("imap.gmail.com", "smtp.gmail.com", 587),
            "outlook": ("outlook.office365.com", "smtp-mail.outlook.com", 587),
            "zoho": ("imap.zoho.in", "smtp.zoho.in", 587)
        }
        if mail_type in mapping:
            return mapping[mail_type]
        if mail_type == "domain":
            return custom_servers.get("imap"), custom_servers.get("smtp"), custom_servers.get("smtp_port", 465)
        raise ValueError(f"Unsupported mail type: {mail_type}")

    def _fetch_unread_emails(self, imap_server, email_user, app_password, inbox_type, allowed_senders):
        """Fetch unread emails from IMAP server."""
        mail = imaplib.IMAP4_SSL(imap_server)
        mail.login(email_user, app_password)
        mail.select("inbox")

        _, data = mail.search(None, "UNSEEN")
        mail_ids = data[0].split()
        emails = []

        for mail_id in mail_ids:
            _, message_data = mail.fetch(mail_id, "(RFC822)")
            msg = email.message_from_bytes(message_data[0][1])
            sender = email.utils.parseaddr(msg.get("From", ""))[1]

            if inbox_type == "specific" and sender not in allowed_senders:
                continue

            subject = msg.get("Subject", "(No Subject)")
            start_time = time.time()
            body = self._extract_email_body(msg)
            log_time("_extract_email_body",start_time)
            attachments = []

            for part in msg.walk():
                if part.get("Content-Disposition", "").startswith("attachment"):
                    attachments.append((part.get_filename(), part.get_payload(decode=True)))

            emails.append({"from": sender, "subject": subject, "body": body, "attachments": attachments})

        mail.logout()
        return emails

    def _extract_email_body(self, msg):
        """Extract text/plain email content."""
        try:
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain" and not part.get("Content-Disposition"):
                        return part.get_payload(decode=True).decode(errors="ignore").strip()
            return msg.get_payload(decode=True).decode(errors="ignore").strip()
        except Exception:
            return "(Unable to extract email body)"

    def _generate_email_pdf(self, email_data, attachments):
        """Generate a visually appealing merged PDF from email + attachments."""
        merger = PdfMerger()

        # --- Step 1: Create a base styled email PDF ---
        email_pdf = BytesIO()
        doc = SimpleDocTemplate(email_pdf, pagesize=A4, leftMargin=50, rightMargin=50, topMargin=50, bottomMargin=50)

        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(name="EmailHeader", fontSize=12, leading=16, spaceAfter=10, textColor=colors.HexColor("#2E4053")))
        styles.add(ParagraphStyle(name="EmailBody", fontSize=11, leading=15, textColor=colors.black))

        elements = []

        # --- Header Table ---
        header_data = [
            ["From:", email_data.get("from", "")],
            ["Subject:", email_data.get("subject", "")]
        ]
        header_table = Table(header_data, colWidths=[70, 400])
        header_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor("#1B2631")),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(header_table)
        elements.append(Spacer(1, 10))
        elements.append(Paragraph("<hr/>", styles["EmailBody"]))

        # --- Body content ---
        for line in email_data["body"].splitlines():
            if line.strip():
                elements.append(Paragraph(line, styles["EmailBody"]))
                elements.append(Spacer(1, 6))
            else:
                elements.append(Spacer(1, 12))

        # Build the base PDF
        doc.build(elements)
        email_pdf.seek(0)
        merger.append(email_pdf)

        # --- Step 2: Merge attachments ---
        for filename, file_bytes in attachments:
            ext = os.path.splitext(filename)[1].lower()
            buffer = BytesIO(file_bytes)

            if ext == ".pdf":
                merger.append(buffer)

            elif ext == ".docx":
                docx_doc = Document(buffer)
                temp_pdf = BytesIO()
                temp_doc = SimpleDocTemplate(temp_pdf, pagesize=A4)
                docx_elements = []
                for para in docx_doc.paragraphs:
                    docx_elements.append(Paragraph(para.text, styles["EmailBody"]))
                    docx_elements.append(Spacer(1, 6))
                temp_doc.build(docx_elements)
                temp_pdf.seek(0)
                merger.append(temp_pdf)

            elif ext == ".txt":
                content = buffer.read().decode(errors="ignore")
                temp_pdf = BytesIO()
                temp_doc = SimpleDocTemplate(temp_pdf, pagesize=A4)
                txt_elements = []
                for line in content.splitlines():
                    txt_elements.append(Paragraph(line, styles["EmailBody"]))
                    txt_elements.append(Spacer(1, 6))
                temp_doc.build(txt_elements)
                temp_pdf.seek(0)
                merger.append(temp_pdf)

            elif ext in [".jpg", ".jpeg", ".png"]:
                img = Image.open(buffer).convert("RGB")
                img_pdf = BytesIO()
                img.save(img_pdf, format="PDF")
                img_pdf.seek(0)
                merger.append(img_pdf)

        # --- Step 3: Combine everything ---
        final_pdf = BytesIO()
        merger.write(final_pdf)
        merger.close()
        final_pdf.seek(0)

        return final_pdf

    def _forward_email(
        self,
        smtp_server,
        smtp_port,
        sender_email,
        app_password,
        recipients,
        subject,
        body,
        attachments=None,
        original_from=None,
        original_date=None,
    ):
        """
        Sends a clean forwarded email with working attachments and single HTML body.
        """

        original_date = original_date or datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # --- Main container: mixed (for body + attachments)
        msg = MIMEMultipart("mixed")
        msg["Subject"] = f"FWD: {subject}"
        msg["From"] = sender_email
        msg["To"] = ", ".join(recipients)

        # --- Alternative part for plain + HTML body
        alternative_part = MIMEMultipart("alternative")

        text_body = f"""
                    From: {original_from or sender_email}
                    Date: {original_date}
                    Subject: {subject}

                    {body}
                    """

        html_body = f"""
                    <html>
                    <body style="font-family: Arial, Helvetica, sans-serif; font-size: 14px; line-height: 1.6; color: #e0e0e0; background-color: #121212; padding: 15px;">
                        <div style="background-color:#1e1e1e; padding:12px; border-radius:8px;">
                            <p><strong>From:</strong> {original_from or sender_email}<br>
                            <strong>Date:</strong> {original_date}<br>
                            <strong>Subject:</strong> {subject}</p>
                        </div>

                        <hr style="border: 0; border-top: 1px solid #333; margin: 20px 0;">

                        <div>{body}</div>
                    </body>
                    </html>
                    """

        alternative_part.attach(MIMEText(text_body, "plain"))
        alternative_part.attach(MIMEText(html_body, "html"))

        # Attach the body part
        msg.attach(alternative_part)

        # --- Attach all files
        if attachments:
            for filename, file_bytes in attachments:
                if not file_bytes:
                    continue
                part = MIMEApplication(file_bytes, Name=os.path.basename(filename))
                part.add_header(
                    "Content-Disposition",
                    f'attachment; filename="{os.path.basename(filename)}"'
                )
                msg.attach(part)

        # --- Send email
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(sender_email, app_password)
            server.sendmail(sender_email, recipients, msg.as_string())


