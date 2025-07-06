import os
from dotenv import load_dotenv
import google.oauth2.credentials
import google.generativeai as genai
import base64
from bs4 import BeautifulSoup
from flask import Flask, redirect, request, session, url_for
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.http import BatchHttpRequest

# Load environment variables from .env file
load_dotenv()

# --- Configuration ---
# Configure Gemini API
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

# Flask app setup
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "a_very_secret_key_for_development")

# Google OAuth Configuration
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1" # For local development only
CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
SCOPES = os.getenv("SCOPES", "https://www.googleapis.com/auth/gmail.readonly").split(',')
REDIRECT_URI = "http://localhost:5000/oauth2callback"

# --- Helper Functions ---

def get_email_body(payload):
    """
    Recursively search for the email's body, preferring plain text.
    Decodes from base64 and cleans HTML.
    """
    # Look for parts in a multipart email
    if "parts" in payload:
        for part in payload['parts']:
            # Prioritize the plain text part
            if part['mimeType'] == 'text/plain':
                data = part['body'].get('data')
                if data:
                    return base64.urlsafe_b64decode(data.encode('ASCII')).decode('utf-8')
        # If no plain text, fall back to HTML
        for part in payload['parts']:
            if part['mimeType'] == 'text/html':
                data = part['body'].get('data')
                if data:
                    decoded_html = base64.urlsafe_b64decode(data.encode('ASCII')).decode('utf-8')
                    # Use BeautifulSoup to strip HTML tags
                    soup = BeautifulSoup(decoded_html, "lxml")
                    return soup.get_text(separator='\n', strip=True)
    # Handle non-multipart emails
    elif "body" in payload and payload['body'].get('data'):
        data = payload['body']['data']
        decoded_data = base64.urlsafe_b64decode(data.encode('ASCII')).decode('utf-8')
        # If the top-level is HTML, clean it
        if payload.get('mimeType') == 'text/html':
            soup = BeautifulSoup(decoded_data, "lxml")
            return soup.get_text(separator='\n', strip=True)
        return decoded_data
        
    return "" # Return empty string if no body is found

def summarize_text(text):
    """Summarizes a given text, truncating it first for efficiency."""
    if not text:
        return "No text to summarize."
    try:
        model = genai.GenerativeModel('gemini-1.5-flash-latest')
        
        # IMPORTANT: Truncate to keep the app lightweight and fast
        truncated_text = text[:15000] 

        prompt = f"Please provide a concise, one-sentence summary of the following email content:\n\n\"{truncated_text}\""
        response = model.generate_content(prompt)
        
        if response.parts:
            return response.text.strip()
        else:
            return "Summary could not be generated (content may be blocked)."
            
    except Exception as e:
        app.logger.error(f"Gemini API call failed: {e}")
        return f"Gemini Error: An error occurred during summarization."


def credentials_to_dict(creds):
    """Converts Google OAuth credentials to a serializable dictionary."""
    return {
        'token': creds.token,
        'refresh_token': creds.refresh_token,
        'token_uri': creds.token_uri,
        'client_id': creds.client_id,
        'client_secret': creds.client_secret,
        'scopes': creds.scopes
    }

# --- Flask Routes ---

@app.route('/')
def index():
    if 'credentials' in session:
        return '<a href="/read_emails">Read and Summarize My Emails</a><br><a href="/logout">Logout</a>'
    return '<a href="/authorize">Connect your Gmail Account</a>'

@app.route('/logout')
def logout():
    session.pop('credentials', None)
    return redirect(url_for('index'))
    
@app.route('/authorize')
def authorize():
    """Starts the OAuth 2.0 authorization flow."""
    flow = Flow.from_client_config(
        client_config={
            "web": {
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
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
    """Handles the OAuth 2.0 callback and stores credentials."""
    state = session.pop('state', None)
    if not state or state != request.args.get('state'):
        return "State mismatch error. Please try authorizing again.", 400
        
    flow = Flow.from_client_config(
        client_config={
            "web": {
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
            }
        },
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI
    )
    flow.fetch_token(authorization_response=request.url)
    session['credentials'] = credentials_to_dict(flow.credentials)
    return redirect(url_for('read_emails'))

@app.route('/read_emails')
def read_emails():
    """Fetches full email bodies using batch requests and displays summaries."""
    creds_data = session.get('credentials')
    if not creds_data:
        return redirect(url_for('authorize'))

    try:
        creds = google.oauth2.credentials.Credentials(**creds_data)
        service = build('gmail', 'v1', credentials=creds)

        list_response = service.users().messages().list(userId='me', maxResults=5).execute()
        messages = list_response.get('messages', [])
        
        if not messages: return "No emails found."

        email_data = {} # Will store {'snippet': '...', 'body': '...'}

        def batch_callback(request_id, response, exception):
            if not exception:
                snippet = response.get('snippet', '')
                # Call our new helper to get the clean body from the payload
                body = get_email_body(response.get('payload', {}))
                email_data[request_id] = {'snippet': snippet, 'body': body}
            else:
                email_data[request_id] = {'snippet': 'Error fetching email.', 'body': ''}

        batch = service.new_batch_http_request(callback=batch_callback)
        for msg in messages:
            msg_id = msg['id']
            # Ask for the 'payload' field to get the full body content
            batch.add(service.users().messages().get(userId='me', id=msg_id, format='full', fields='id,snippet,payload'), request_id=msg_id)
        
        batch.execute()

        output = '<h3>Your Last 5 Email Summaries:</h3>'
        for msg in messages:
            data = email_data.get(msg['id'], {})
            snippet = data.get('snippet', 'Snippet not found.')
            body = data.get('body', '')
            
            summary = summarize_text(body) # Summarize the full body
            
            output += f"<p><b>Original Snippet:</b> {snippet}</p>"
            output += f"<p><b>AI Summary:</b> {summary}</p><hr>"

        output += '<a href="/logout">Logout</a>'
        return output

    except Exception as e:
        app.logger.error("An error occurred in /read_emails: %s", e, exc_info=True)
        if 'invalid_grant' in str(e).lower():
            return 'Your authentication has expired. Please <a href="/logout">logout</a> and connect again.'
        return f"An internal error occurred. Please try again later. Details: {e}", 500

if __name__ == '__main__':
    app.run(port=5000, debug=True)