from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


ROOT = Path(r"F:\Windows-Service-Process-Monitoring-Agent")
OUTPUT = ROOT / "output" / "pdf" / "windows_monitoring_agent_summary.pdf"


def bullet(text: str) -> str:
    return f'<bullet>&bull;</bullet>{text}'


def section(title: str, body):
    return KeepTogether([title, Spacer(1, 0.05 * inch), *body, Spacer(1, 0.09 * inch)])


def build_pdf():
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    doc = SimpleDocTemplate(
        str(OUTPUT),
        pagesize=letter,
        leftMargin=0.52 * inch,
        rightMargin=0.52 * inch,
        topMargin=0.48 * inch,
        bottomMargin=0.48 * inch,
        title="Windows Monitoring Agent Summary",
        author="OpenAI Codex",
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "Title",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#12324a"),
        spaceAfter=4,
    )
    subtitle_style = ParagraphStyle(
        "Subtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=10.5,
        textColor=colors.HexColor("#496273"),
        spaceAfter=8,
    )
    h_style = ParagraphStyle(
        "Heading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=10.2,
        leading=12,
        textColor=colors.HexColor("#12324a"),
        spaceAfter=0,
    )
    body_style = ParagraphStyle(
        "Body",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=8.4,
        leading=10.3,
        textColor=colors.HexColor("#1b1b1b"),
        spaceAfter=2,
    )
    bullet_style = ParagraphStyle(
        "Bullet",
        parent=body_style,
        leftIndent=9,
        firstLineIndent=-6,
        bulletIndent=0,
        spaceAfter=1.5,
    )
    small_style = ParagraphStyle(
        "Small",
        parent=body_style,
        fontSize=7.8,
        leading=9.4,
        textColor=colors.HexColor("#36454f"),
    )

    story = [
        Paragraph("Windows Service &amp; Process Monitoring Agent", title_style),
        Paragraph(
            "Repo summary based on README and Python source modules in the current repository.",
            subtitle_style,
        ),
    ]

    what_it_is = [
        Paragraph(
            "A Windows-focused defensive security CLI that inspects running processes and installed services to flag suspicious behavior, paths, and startup configurations.",
            body_style,
        ),
        Paragraph(
            "The implementation centers on Python modules that enumerate system state, generate alerts, and write reports; the repo also contains a minimal Vite/React shell with an empty app component.",
            body_style,
        ),
    ]

    who_its_for = [
        Paragraph(
            "Primary persona: Windows security analysts, incident responders, or defensive engineers who need quick host-level visibility into suspicious processes and services.",
            body_style,
        )
    ]

    key_features = [
        Paragraph(bullet("Enumerates active processes with PID, parent PID, executable path, command line, username, and creation time."), bullet_style),
        Paragraph(bullet("Builds a process tree and flags suspicious parent-child relationships from configured rules."), bullet_style),
        Paragraph(bullet("Detects blacklisted processes and processes running from suspicious paths such as Temp, Public, and Roaming locations."), bullet_style),
        Paragraph(bullet("Flags potential process injection indicators when a process lacks a valid executable path."), bullet_style),
        Paragraph(bullet("Enumerates Windows services, audits service paths and auto-start services, and detects new services against a saved baseline."), bullet_style),
        Paragraph(bullet("Prints color-coded severity alerts and saves machine-readable alert logs as JSON under logs/."), bullet_style),
        Paragraph(bullet("Generates timestamped text reports with executive summary, alert details, service analysis, and recommendations."), bullet_style),
    ]

    architecture_rows = [
        ["Entry point", "monitor_agent.py parses CLI args and orchestrates scans, continuous mode, baseline creation, and comparisons."],
        ["Process path", "ProcessAnalyzer uses psutil to enumerate processes, build the process tree, and detect relationships, blacklisted binaries, and injection indicators."],
        ["Service path", "ServiceAuditor uses pywin32 service APIs to enumerate services, inspect configs, detect suspicious paths, and compare against a baseline."],
        ["Detection config", "config.py stores whitelists, blacklists, suspicious paths, severity labels, and relationship rules used by the analyzers."],
        ["Alert/report flow", "Findings are added to AlertManager for console output and JSON logging, then passed to ReportGenerator for a text report in reports/."],
        ["Frontend note", "src/main.tsx mounts src/app/App.tsx, but App returns an empty container; no UI-to-backend integration was found in repo."],
    ]
    architecture_table = Table(
        architecture_rows,
        colWidths=[1.15 * inch, 5.95 * inch],
        hAlign="LEFT",
    )
    architecture_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eaf1f5")),
                ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#1b1b1b")),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                ("LEADING", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#b8c8d4")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )

    how_to_run = [
        Paragraph(bullet("Use Windows with Python 3.7+; README recommends administrator privileges for fuller visibility."), bullet_style),
        Paragraph(bullet("Install dependencies: <font name='Courier'>pip install -r requirements.txt</font>"), bullet_style),
        Paragraph(bullet("Run one scan: <font name='Courier'>python monitor_agent.py</font>"), bullet_style),
        Paragraph(bullet("Optional: continuous mode with <font name='Courier'>--continuous --interval 300</font>; baseline creation with <font name='Courier'>--baseline</font>; compare with <font name='Courier'>--compare &lt;file&gt;</font>"), bullet_style),
        Paragraph(bullet("Frontend dev/build steps exist in package.json via Vite (<font name='Courier'>dev</font>, <font name='Courier'>build</font>), but a user-facing web workflow was Not found in repo."), bullet_style),
    ]

    footer = Paragraph(
        "Items marked \"Not found in repo\" were not evidenced in the checked-in code or README.",
        small_style,
    )

    story.extend(
        [
            section(Paragraph("What It Is", h_style), what_it_is),
            section(Paragraph("Who It's For", h_style), who_its_for),
            section(Paragraph("What It Does", h_style), key_features),
            section(Paragraph("How It Works", h_style), [architecture_table]),
            section(Paragraph("How To Run", h_style), how_to_run),
            footer,
        ]
    )

    doc.build(story)
    print(OUTPUT)


if __name__ == "__main__":
    build_pdf()
