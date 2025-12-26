# ==============================================================================
# PROPERTY OF CYBER CRIME WING - TAMIL NADU POLICE
# PROJECT: SHADOWFINGERPRINT (Tor Origin Identification System)
# HACKATHON: TN Police Hackathon 2025
# ==============================================================================
from report_generator import ForensicPDF

def convert_report_to_pdf(report_data):
    pdf = ForensicPDF()
    pdf.add_page()
    # Ensure margins are standard (10mm = 1cm)
    pdf.set_margins(15, 15, 15) 
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_text_color(0, 0, 0)
    
    # Metadata
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(40, 10, "Case ID:", 0, 0) # Width 40 for label
    pdf.set_font("Helvetica", "", 11)
    pdf.cell(0, 10, str(report_data['case_metadata']['case_id']), ln=True) # 0 = to margin
    
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(40, 10, "Generated On:", 0, 0)
    pdf.set_font("Helvetica", "", 11)
    gen_date = str(report_data['case_metadata']['generated_on'])[:19]
    pdf.cell(0, 10, gen_date, ln=True)
    pdf.ln(5)
    
    # Helper for full-width section titles
    def add_section_title(title):
        pdf.set_fill_color(240, 240, 240)
        pdf.set_font("Helvetica", "B", 12)
        # Width 0 ensures it fills the available horizontal space
        pdf.cell(0, 10, f"  {title}", ln=True, fill=True)
        pdf.ln(3)

    # Content Sections
    add_section_title("CASE OVERVIEW")
    pdf.set_font("Helvetica", "", 10)
    pdf.multi_cell(0, 6, str(report_data['case_overview']))
    pdf.ln(5)

    add_section_title("ANALYSIS METHODOLOGY")
    for step in report_data['analysis_methodology']:
        pdf.set_x(20) 
        # Cleanly render the 6 steps now present in your methodology
        pdf.multi_cell(0, 6, f"> {str(step)}")
    pdf.ln(5)

    add_section_title("KEY FINDINGS")
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(200, 0, 0)
    pdf.cell(40, 10, "Top Suspect IP:", 0, 0)
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, str(report_data['key_findings']['top_suspect']), ln=True)
    
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(40, 10, "Confidence Score:", 0, 0)
    pdf.set_font("Helvetica", "", 11)
    score = report_data['key_findings']['confidence_score']
    if score < 1: score *= 100
    pdf.cell(0, 10, f"{round(score, 1)}%", ln=True)
    pdf.ln(10)

    add_section_title("LEGAL & ETHICAL NOTICE")
    pdf.set_font("Helvetica", "I", 9)
    pdf.set_text_color(100, 100, 100)
    pdf.multi_cell(0, 5, str(report_data['legal_notice']))

    return pdf.output()