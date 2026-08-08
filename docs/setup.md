# Setup Guide

## 1. Requirements

The Password Security Analyzer requires:

- Python 3.13+
- pip
- Git
- Internet connectivity for HIBP API checks
- A valid Have I Been Pwned API key for email breach checking

The application can run locally on Linux, Windows, or macOS.

---

## 2. Clone the Project

```bash
git clone <repository-url>
cd pass

Create a Virtual Environment

Linux/macOS:

python3 -m venv .venv

Activate it:

source .venv/bin/activate

Windows:

python -m venv .venv

Activate:

.venv\Scripts\activate

Install Dependencies

Install the dependencies captured from the project's virtual environment:

pip install -r requirements.txt

python app.py

Start Watchdog

Watchdog should run separately from Flask.

Open another terminal:

cd /path/to/pass
source .venv/bin/activate
python services/watchdog_service.py

