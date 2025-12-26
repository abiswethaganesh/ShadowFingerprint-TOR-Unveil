# ==============================================================================
# PROPERTY OF CYBER CRIME WING - TAMIL NADU POLICE
# PROJECT: SHADOWFINGERPRINT (Tor Origin Identification System)
# HACKATHON: TN Police Hackathon 2025
# ==============================================================================

from fpdf import FPDF
import os

class ForensicPDF(FPDF):
    def header(self):
        # Professional Watermark Logic (8% Opacity)
        logo_path = "backend/data/img.jpeg" 
        if os.path.exists(logo_path):
            with self.local_context(fill_opacity=0.08):
                # Centers the logo on A4
                self.image(logo_path, x=35, y=60, w=140)
        
        # Professional Header Bar (Dark Navy)
        self.set_fill_color(26, 26, 46) 
        self.rect(0, 0, 210, 40, 'F')
        
        self.set_font("Helvetica", "B", 16)
        self.set_text_color(255, 255, 255)
        self.cell(0, 10, "CYBER CRIME WING - TAMIL NADU POLICE", ln=True, align="C")
        self.set_font("Helvetica", "", 12)
        self.cell(0, 10, "OFFICIAL FORENSIC INVESTIGATION REPORT", ln=True, align="C")
        self.ln(20)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f"Page {self.page_no()} | Restricted - Law Enforcement Use Only", align="C")