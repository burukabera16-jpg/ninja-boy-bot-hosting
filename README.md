# NINJA BOY BOT HOSTING

This repository contains a Vercel-compatible Flask dashboard for hosting Telegram bots, including admin authentication, Telegram API profile reading, bot registration, Python script upload, and worker integration.

## Requirements

- Python 3.11+
- Virtual environment recommended
- Access to a persistent worker service for long-running bots

## Local setup

1. Clone the repo.
2. Create a virtual environment.
3. Install dependencies:
   `pip install -r requirements.txt`
4. Copy `.env.example` to `.env` and fill in your values.
5. Start the app:
   `python app.py`
6. Open the dashboard at `http://localhost:5000`.

## Worker service

A persistent worker should run separately on a host that remains online. Example:

```
python worker/worker.py
```

The worker listens on port `9001` by default and verifies the `X-Worker-Secret` header.

## Vercel deployment

- Connect the repo to Vercel.
- Set environment variables in the Vercel project settings.
- Use the included `vercel.json` file.
- Note that long-running bot processes should not run inside Vercel serverless functions.

## Security

- Keep secrets out of source control.
- Never expose Telegram tokens to the frontend.
- Use secure session cookies in production.
- Store only encrypted bot tokens.
- Keep uploaded Python scripts in a private folder outside the public web root.

## Notes

This is a functional starter project aligned with your specification. For production, use Postgres, object storage, and a dedicated worker host.
