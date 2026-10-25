# Phishing Awareness Analyzer

Cyber Security Internship — Project 3  
Decode Labs | October 2026

## Overview

A Python-based phishing awareness and message analysis tool developed
as part of the Decode Labs Cyber Security Internship.

The application analyzes email and message content for common phishing
indicators and calculates a basic phishing risk score.

## Features

- Suspicious keyword detection
- URL extraction and analysis
- Suspicious domain detection
- Phishing risk scoring
- Safe, Suspicious, and Malicious classification
- Recommended incident response action
- Phishing red flags checklist
- Sample phishing messages
- Automated unit testing

## Classification

- SAFE → CLOSE
- SUSPICIOUS → WARN USER
- MALICIOUS → BLOCK & ESCALATE

## Security Principle

PAUSE → VERIFY → REPORT

## Technologies

- Python 3
- Regular Expressions
- urllib.parse
- unittest
- Git
- GitHub

## Project Files

- `phishing_analyzer.py` — Main phishing analysis tool
- `test_phishing_analyzer.py` — Automated unit tests
- `sample_messages.txt` — Safe and phishing message examples
- `RED_FLAGS_CHECKLIST.md` — Phishing identification checklist

## How to Run

```bash
python3 phishing_analyzer.py