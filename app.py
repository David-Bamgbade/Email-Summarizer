from dotenv import load_dotenv
load_dotenv()

from flask import Flask, redirect, request, session, url_for
import os
import openai
openai.api_key = os.getenv("OPENAI_API_KEY")
import google.auth.transport.requests

from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
import google.oauth2.credentials



openai_keyss = openai.api_key = os.getenv("OPENAI_API_KEY")
CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
SCOPES = os.getenv("SCOPES")

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "default_dev_secret")  # use env var




# Enable OAuth for local development
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

REDIRECT_URI = "http://localhost:5000/oauth2callback"

def summarize_text(text):
    try:
        client = openai.OpenAI(api_key=openai_keyss)
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",  
            messages=[
                {"role": "system", "content": "You are an AI assistant that summarizes emails."},
                {"role": "user", "content": f"Summarize this email: {text}"}
            ],
            max_tokens=100
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        return f"Error: {e}"



@app.route('/')
def index():
    return '<a href="/authorize">Connect your Gmail</a>'

@app.route('/authorize')
def authorize():
    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",  # ✅ FIXED
                "token_uri": "https://oauth2.googleapis.com/token",
            }
        },
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI
    )
    auth_url, state = flow.authorization_url(access_type='offline', include_granted_scopes='true')
    session['state'] = state
    return redirect(auth_url)

@app.route('/oauth2callback')
def oauth2callback():
    state = session.get('state')
    if not state:
        return "Session expired or invalid. Please go to /authorize first.", 400

    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
            }
        },
        scopes=SCOPES,
        state=state,
        redirect_uri=REDIRECT_URI
    )
    flow.fetch_token(authorization_response=request.url)

    credentials = flow.credentials
    session['credentials'] = credentials_to_dict(credentials)

    return redirect(url_for('read_emails'))

@app.route('/read_emails')
def read_emails():
    creds_data = session.get('credentials')
    if not creds_data:
        return redirect(url_for('authorize'))

    creds = google.oauth2.credentials.Credentials(**creds_data)
    service = build('gmail', 'v1', credentials=creds)

    results = service.users().messages().list(userId='me', maxResults=5).execute()
    messages = results.get('messages', [])

    output = '<h3>Your Last 5 Email Snippets:</h3>'
    for msg in messages:
        msg_data = service.users().messages().get(userId='me', id=msg['id']).execute()
        snippet = msg_data.get('snippet')
        summary = summarize_text(snippet)
        output += f"<p><b>Original:</b> {snippet}</p>"
        output += f"<p><b>Summary:</b> {summary}</p><hr>"""

    return output


def credentials_to_dict(creds):
    return {
        'token': creds.token,
        'refresh_token': creds.refresh_token,
        'token_uri': creds.token_uri,
        'client_id': creds.client_id,
        'client_secret': creds.client_secret,
        'scopes': creds.scopes
    }

if __name__ == '__main__':
    app.run(port=5000, debug=True)
