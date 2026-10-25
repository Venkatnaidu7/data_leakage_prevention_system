#!/usr/bin/env python3
"""Script to generate DLP_Defender_Beginner_Guide.docx from DLP_Defender_Beginner_Guide.md.

Applies professional typography, colored headers, shaded tables, callout boxes,
and monospaced syntax-highlighted code blocks.
"""

import re
import sys
from pathlib import Path
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import nsdecls, qn

def set_cell_background(cell, hex_color):
    """Set the background color of a table cell."""
    shading_elm = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{hex_color}"/>')
    cell._tc.get_or_add_tcPr().append(shading_elm)

def set_cell_margins(cell, top=100, bottom=100, left=150, right=150):
    """Set cell internal padding in dxa (1 pt = 20 dxa)."""
    tcPr = cell._tc.get_or_add_tcPr()
    tcMar = OxmlElement('w:tcMar')
    for m, val in [('top', top), ('bottom', bottom), ('left', left), ('right', right)]:
        node = OxmlElement(f'w:{m}')
        node.set(qn('w:w'), str(val))
        node.set(qn('w:type'), 'dxa')
        tcMar.append(node)
    tcPr.append(tcMar)

def set_table_borders(table, color="CCCCCC", sz="4", val="single"):
    """Set subtle borders for a table."""
    tblPr = table._tbl.tblPr
    borders = parse_xml(
        f'<w:tblBorders {nsdecls("w")}>'
        f'  <w:top w:val="{val}" w:sz="{sz}" w:space="0" w:color="{color}"/>'
        f'  <w:bottom w:val="{val}" w:sz="{sz}" w:space="0" w:color="{color}"/>'
        f'  <w:insideH w:val="{val}" w:sz="{sz}" w:space="0" w:color="{color}"/>'
        f'  <w:insideV w:val="none"/>'
        f'  <w:left w:val="none"/>'
        f'  <w:right w:val="none"/>'
        f'</w:tblBorders>'
    )
    tblPr.append(borders)

def set_callout_border(cell, color_hex="2B6CB0", border_sz="24"):
    """Set a thick left border for callout blocks."""
    tcPr = cell._tc.get_or_add_tcPr()
    borders = parse_xml(
        f'<w:tcBorders {nsdecls("w")}>'
        f'  <w:left w:val="single" w:sz="{border_sz}" w:space="0" w:color="{color_hex}"/>'
        f'  <w:top w:val="none"/>'
        f'  <w:bottom w:val="none"/>'
        f'  <w:right w:val="none"/>'
        f'</w:tcBorders>'
    )
    tcPr.append(borders)

def build_docx(md_path: Path, docx_path: Path):
    doc = Document()

    # Set page margins (1 inch)
    sections = doc.sections
    for section in sections:
        section.top_margin = Inches(1)
        section.bottom_margin = Inches(1)
        section.left_margin = Inches(1)
        section.right_margin = Inches(1)

    # Base styles
    normal_style = doc.styles['Normal']
    normal_style.font.name = 'Calibri'
    normal_style.font.size = Pt(10.5)
    normal_style.font.color.rgb = RGBColor(0x2D, 0x37, 0x48)  # Charcoal
    normal_style.paragraph_format.line_spacing = 1.15
    normal_style.paragraph_format.space_after = Pt(4)

    with open(md_path, 'r', encoding='utf-8') as f:
        md_text = f.read()

    lines = md_text.splitlines()
    i = 0
    total_lines = len(lines)

    in_code_block = False
    code_lines = []
    code_lang = ""

    while i < total_lines:
        line = lines[i]

        # Check for code block toggle
        if line.startswith("```"):
            if not in_code_block:
                in_code_block = True
                code_lang = line[3:].strip()
                code_lines = []
                i += 1
                continue
            else:
                in_code_block = False
                # Render code block as a stylized table
                code_text = "\n".join(code_lines)
                table = doc.add_table(rows=1, cols=1)
                table.alignment = WD_TABLE_ALIGNMENT.CENTER
                cell = table.cell(0, 0)
                set_cell_background(cell, "F7FAFC")
                set_callout_border(cell, color_hex="4A5568", border_sz="12")
                set_cell_margins(cell, top=140, bottom=140, left=200, right=140)

                p = cell.paragraphs[0]
                p.paragraph_format.space_before = Pt(2)
                p.paragraph_format.space_after = Pt(2)
                p.paragraph_format.line_spacing = 1.05
                run = p.add_run(code_text)
                run.font.name = 'Consolas'
                run.font.size = Pt(9.0)
                run.font.color.rgb = RGBColor(0x1A, 0x20, 0x2C)

                doc.add_paragraph()  # Spacing
                i += 1
                continue

        if in_code_block:
            code_lines.append(line)
            i += 1
            continue

        # Markdown Table detection
        if line.startswith("|") and line.endswith("|"):
            table_lines = []
            while i < total_lines and lines[i].startswith("|") and lines[i].endswith("|"):
                table_lines.append(lines[i])
                i += 1

            if len(table_lines) >= 2:
                # Parse markdown table
                headers = [c.strip() for c in table_lines[0].strip("|").split("|")]
                # Skip separator row (table_lines[1])
                data_rows = []
                for row_line in table_lines[2:]:
                    cells = [c.strip() for c in row_line.strip("|").split("|")]
                    if len(cells) == len(headers):
                        data_rows.append(cells)
                    elif len(cells) < len(headers):
                        cells += [""] * (len(headers) - len(cells))
                        data_rows.append(cells)
                    else:
                        data_rows.append(cells[:len(headers)])

                table = doc.add_table(rows=len(data_rows) + 1, cols=len(headers))
                table.alignment = WD_TABLE_ALIGNMENT.CENTER
                set_table_borders(table, color="CBD5E0", sz="4")

                # Header formatting
                hdr_cells = table.rows[0].cells
                for col_idx, h_text in enumerate(headers):
                    cell = hdr_cells[col_idx]
                    set_cell_background(cell, "1A365D")  # Deep Navy
                    set_cell_margins(cell, top=140, bottom=140, left=140, right=140)
                    p = cell.paragraphs[0]
                    p.paragraph_format.space_before = Pt(2)
                    p.paragraph_format.space_after = Pt(2)
                    # Clean markdown bold markers
                    clean_h = h_text.replace("**", "").replace("*", "")
                    run = p.add_run(clean_h)
                    run.font.bold = True
                    run.font.size = Pt(9.5)
                    run.font.name = 'Calibri'
                    run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)

                # Data row formatting
                for r_idx, row_data in enumerate(data_rows):
                    row_cells = table.rows[r_idx + 1].cells
                    row_bg = "F7FAFC" if (r_idx % 2 == 1) else "FFFFFF"
                    for col_idx, cell_value in enumerate(row_data):
                        cell = row_cells[col_idx]
                        set_cell_background(cell, row_bg)
                        set_cell_margins(cell, top=100, bottom=100, left=140, right=140)
                        p = cell.paragraphs[0]
                        p.paragraph_format.space_before = Pt(2)
                        p.paragraph_format.space_after = Pt(2)

                        # Clean cell text formatting
                        # Handle code inside cell `...` or bold **...**
                        parts = re.split(r'(`[^`]+`|\*\*[^*]+\*\*)', cell_value)
                        for part in parts:
                            if not part:
                                continue
                            if part.startswith('`') and part.endswith('`'):
                                run = p.add_run(part[1:-1])
                                run.font.name = 'Consolas'
                                run.font.size = Pt(8.5)
                                run.font.color.rgb = RGBColor(0xC5, 0x30, 0x30)
                            elif part.startswith('**') and part.endswith('**'):
                                run = p.add_run(part[2:-2])
                                run.font.bold = True
                                run.font.name = 'Calibri'
                                run.font.size = Pt(9.0)
                                if "[SAFE]" in part:
                                    run.font.color.rgb = RGBColor(0x22, 0x54, 0x3D)
                                elif "[CAUTION]" in part:
                                    run.font.color.rgb = RGBColor(0xC0, 0x56, 0x21)
                                elif "[DESTRUCTIVE]" in part:
                                    run.font.color.rgb = RGBColor(0x9B, 0x2C, 0x2C)
                            else:
                                run = p.add_run(part)
                                run.font.name = 'Calibri'
                                run.font.size = Pt(9.0)

                doc.add_paragraph()  # Spacing after table
            continue

        # Blockquote / Callout detection
        if line.startswith(">"):
            quote_lines = []
            while i < total_lines and lines[i].startswith(">"):
                quote_lines.append(lines[i].lstrip("> ").strip())
                i += 1

            quote_text = " ".join(quote_lines)
            border_color = "2B6CB0"
            bg_color = "EBF8FF"
            callout_type = "NOTE"

            if "[!NOTE]" in quote_text:
                callout_type = "NOTE"
                border_color = "2B6CB0"
                bg_color = "EBF8FF"
                quote_text = quote_text.replace("[!NOTE]", "").strip()
            elif "[!TIP]" in quote_text:
                callout_type = "TIP"
                border_color = "234E52"
                bg_color = "E6FFFA"
                quote_text = quote_text.replace("[!TIP]", "").strip()
            elif "[!CAUTION]" in quote_text or "[!WARNING]" in quote_text:
                callout_type = "CAUTION"
                border_color = "9B2C2C"
                bg_color = "FFF5F5"
                quote_text = quote_text.replace("[!CAUTION]", "").replace("[!WARNING]", "").strip()

            table = doc.add_table(rows=1, cols=1)
            table.alignment = WD_TABLE_ALIGNMENT.CENTER
            cell = table.cell(0, 0)
            set_cell_background(cell, bg_color)
            set_callout_border(cell, color_hex=border_color, border_sz="24")
            set_cell_margins(cell, top=140, bottom=140, left=180, right=140)

            p = cell.paragraphs[0]
            p.paragraph_format.space_before = Pt(2)
            p.paragraph_format.space_after = Pt(2)
            prefix = p.add_run(f"[{callout_type}] ")
            prefix.bold = True
            prefix.font.size = Pt(10)
            if callout_type == "CAUTION":
                prefix.font.color.rgb = RGBColor(0x9B, 0x2C, 0x2C)
            elif callout_type == "TIP":
                prefix.font.color.rgb = RGBColor(0x23, 0x4E, 0x52)
            else:
                prefix.font.color.rgb = RGBColor(0x2B, 0x6C, 0xB0)

            run = p.add_run(quote_text)
            run.font.size = Pt(10)
            run.font.italic = True
            doc.add_paragraph()
            continue

        # Headers
        if line.startswith("# ") and not line.startswith("## "):
            h_text = line[2:].strip()
            p = doc.add_paragraph()
            p.paragraph_format.space_before = Pt(18)
            p.paragraph_format.space_after = Pt(6)
            run = p.add_run(h_text)
            run.font.name = 'Calibri'
            run.font.size = Pt(22)
            run.font.bold = True
            run.font.color.rgb = RGBColor(0x1A, 0x36, 0x5D)  # Deep Navy
            i += 1
            continue

        if line.startswith("## "):
            h_text = line[3:].strip()
            p = doc.add_paragraph()
            p.paragraph_format.space_before = Pt(16)
            p.paragraph_format.space_after = Pt(4)
            run = p.add_run(h_text)
            run.font.name = 'Calibri'
            run.font.size = Pt(15)
            run.font.bold = True
            run.font.color.rgb = RGBColor(0x2B, 0x6C, 0xB0)  # Blue
            i += 1
            continue

        if line.startswith("### "):
            h_text = line[4:].strip()
            p = doc.add_paragraph()
            p.paragraph_format.space_before = Pt(12)
            p.paragraph_format.space_after = Pt(3)
            run = p.add_run(h_text)
            run.font.name = 'Calibri'
            run.font.size = Pt(12)
            run.font.bold = True
            run.font.color.rgb = RGBColor(0x2D, 0x37, 0x48)  # Charcoal
            i += 1
            continue

        if line.startswith("#### "):
            h_text = line[5:].strip()
            p = doc.add_paragraph()
            p.paragraph_format.space_before = Pt(8)
            p.paragraph_format.space_after = Pt(2)
            run = p.add_run(h_text)
            run.font.name = 'Calibri'
            run.font.size = Pt(11)
            run.font.bold = True
            run.font.color.rgb = RGBColor(0x4A, 0x55, 0x68)
            i += 1
            continue

        # Horizontal rule
        if line.strip() in ("---", "***", "___"):
            p = doc.add_paragraph()
            p.paragraph_format.space_before = Pt(6)
            p.paragraph_format.space_after = Pt(6)
            run = p.add_run("_________________________________________________________________________________")
            run.font.size = Pt(8)
            run.font.color.rgb = RGBColor(0xCB, 0xD5, 0xE0)
            i += 1
            continue

        # List items
        is_bullet = line.startswith("- ") or line.startswith("* ")
        is_num = bool(re.match(r'^\d+\.\s', line))

        if is_bullet or is_num:
            if is_bullet:
                item_text = line[2:].strip()
                p = doc.add_paragraph(style='List Bullet')
            else:
                item_text = re.sub(r'^\d+\.\s', '', line).strip()
                p = doc.add_paragraph(style='List Number')

            p.paragraph_format.space_before = Pt(1)
            p.paragraph_format.space_after = Pt(2)
            p.paragraph_format.line_spacing = 1.15

            # Parse inline formatting: `code`, **bold**, *italic*
            parts = re.split(r'(`[^`]+`|\*\*[^*]+\*\*|\*[^*]+\*)', item_text)
            for part in parts:
                if not part:
                    continue
                if part.startswith('`') and part.endswith('`'):
                    run = p.add_run(part[1:-1])
                    run.font.name = 'Consolas'
                    run.font.size = Pt(9.5)
                    run.font.color.rgb = RGBColor(0xC5, 0x30, 0x30)
                elif part.startswith('**') and part.endswith('**'):
                    run = p.add_run(part[2:-2])
                    run.font.bold = True
                    if "[SAFE]" in part:
                        run.font.color.rgb = RGBColor(0x22, 0x54, 0x3D)
                    elif "[CAUTION]" in part:
                        run.font.color.rgb = RGBColor(0xC0, 0x56, 0x21)
                    elif "[DESTRUCTIVE]" in part:
                        run.font.color.rgb = RGBColor(0x9B, 0x2C, 0x2C)
                elif part.startswith('*') and part.endswith('*'):
                    run = p.add_run(part[1:-1])
                    run.font.italic = True
                else:
                    p.add_run(part)

            i += 1
            continue

        # Regular paragraphs
        if line.strip():
            p = doc.add_paragraph()
            p.paragraph_format.space_before = Pt(2)
            p.paragraph_format.space_after = Pt(4)
            p.paragraph_format.line_spacing = 1.15

            parts = re.split(r'(`[^`]+`|\*\*[^*]+\*\*|\*[^*]+\*)', line)
            for part in parts:
                if not part:
                    continue
                if part.startswith('`') and part.endswith('`'):
                    run = p.add_run(part[1:-1])
                    run.font.name = 'Consolas'
                    run.font.size = Pt(9.5)
                    run.font.color.rgb = RGBColor(0xC5, 0x30, 0x30)
                elif part.startswith('**') and part.endswith('**'):
                    run = p.add_run(part[2:-2])
                    run.font.bold = True
                    if "[SAFE]" in part:
                        run.font.color.rgb = RGBColor(0x22, 0x54, 0x3D)
                    elif "[CAUTION]" in part:
                        run.font.color.rgb = RGBColor(0xC0, 0x56, 0x21)
                    elif "[DESTRUCTIVE]" in part:
                        run.font.color.rgb = RGBColor(0x9B, 0x2C, 0x2C)
                elif part.startswith('*') and part.endswith('*'):
                    run = p.add_run(part[1:-1])
                    run.font.italic = True
                else:
                    p.add_run(part)

        i += 1

    doc.save(docx_path)
    print(f"[+] Successfully generated Word document: {docx_path}")

if __name__ == "__main__":
    repo_dir = Path(__file__).resolve().parent.parent
    md_file = repo_dir / "DLP_Defender_Beginner_Guide.md"
    docx_file = repo_dir / "DLP_Defender_Beginner_Guide.docx"

    if not md_file.exists():
        print(f"[-] Error: Markdown file not found at {md_file}")
        sys.exit(1)

    build_docx(md_file, docx_file)
