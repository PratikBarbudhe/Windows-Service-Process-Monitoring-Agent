# Windows Service Process Monitoring Agent

Production-ready Python refactor with modular layout:

- `app` - core logic, config, logging, monitoring
- `api` - FastAPI application
- `dashboard` - Streamlit UI
- `services` - Windows service loop support
- `cli` - command-line commands

## Install

```bash
pip install -r requirements.txt
copy .env.example .env
```

## Run

```bash
# agent CLI
python main.py

# FastAPI server
uvicorn api.api_server:app --reload

# Streamlit dashboard
streamlit run dashboard/dashboard_streamlit.py
```

Run as Administrator on Windows for full process visibility.
