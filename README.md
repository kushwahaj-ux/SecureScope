# 🔐 SecureScope — AI-Powered Vulnerability Scanner

## What is SecureScope?
SecureScope is an enterprise-level combined SAST + DAST vulnerability scanner 
built with Python and Gemini AI. It automatically discovers vulnerabilities in 
websites and networks, cross-references findings with the US Government CVE 
database, and generates professional PDF reports with AI-powered analysis.

## Features
- Network port scanning using Nmap
- Web vulnerability detection (OWASP Top 10)
- Static code analysis (SAST)
- US Government NVD CVE database integration
- AI-powered analysis using Google Gemini
- Risk scoring system
- Professional PDF report generation
- MariaDB for scan history storage
- Flask web dashboard

## Tech Stack
- Python 3.10+
- Google Gemini AI
- MariaDB
- Flask
- Nmap
- ReportLab
- BeautifulSoup4

## Installation
```bash
git clone https://github.com/yourusername/SecureScope
cd SecureScope
pip install -r requirements.txt
```

## Setup
1. Get free Gemini API key at aistudio.google.com
2. Set environment variable:
```bash
export GEMINI_API_KEY="your-key-here"
```
3. Install MariaDB and create database:
```sql
CREATE DATABASE securescope;
```
4. Run:
```bash
python app.py
```
5. Open http://localhost:5000

## Legal Targets for Testing
- scanme.nmap.org
- testphp.vulnweb.com
- Your own websites

## Author
Ajeet Kumar — MCA Graduate | Cybersecurity Enthusiast