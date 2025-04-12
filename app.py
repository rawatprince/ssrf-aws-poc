import requests
from flask import Flask, request, render_template, jsonify
import json # Import json for better header display

# --- Security Warning ---
# This application is intentionally vulnerable to SSRF for PoC purposes.
# It takes user-supplied URLs and makes server-side requests to them.
# DO NOT expose this application publicly. Restrict access via Security Groups.
# --- End Security Warning ---

app = Flask(__name__)

def parse_headers(raw_headers_str):
    """ Parses header string (Header: Value\n...) into a dictionary. """
    headers = {}
    if not raw_headers_str:
        return headers
    lines = raw_headers_str.strip().split('\n')
    for line in lines:
        line = line.strip()
        if ':' in line:
            key, value = line.split(':', 1)
            headers[key.strip()] = value.strip()
        elif line: # Handle lines without colons potentially? For now, just ignore.
            app.logger.warning(f"Ignoring malformed header line: {line}")
    return headers

@app.route('/', methods=['GET'])
def index():
    """ Renders the initial form page. """
    return render_template('index.html')

@app.route('/fetch', methods=['POST'])
def fetch_url():
    """
    Receives form data, makes the specified HTTP request server-side,
    and returns the response details to the frontend.
    """
    url = request.form.get('url')
    method = request.form.get('method')
    raw_headers = request.form.get('headers', '')
    body = request.form.get('body', None) # Use None if empty for requests lib

    # Basic validation
    if not url or not method:
        return render_template('index.html',
                               response={'error': 'URL and Method are required.'},
                               form_data=request.form)

    headers_dict = parse_headers(raw_headers)

    # Prepare data - requests expects None or bytes/string for data
    request_data = body if body else None
    if request_data and isinstance(request_data, str):
       # Try to encode body as UTF-8, common for web requests
       try:
           request_data = request_data.encode('utf-8')
       except Exception as e:
           app.logger.error(f"Could not encode body: {e}")
           return render_template('index.html',
                                  response={'error': f'Could not encode request body: {e}'},
                                  form_data=request.form)

    response_data = {}
    try:
        app.logger.info(f"Making {method} request to {url} with headers {headers_dict}")
        resp = requests.request(
            method=method,
            url=url,
            headers=headers_dict,
            data=request_data,
            timeout=10, # Add a timeout to prevent hanging
            allow_redirects=True # Follow redirects by default
        )

        # Process response for display
        response_data['status_code'] = resp.status_code
        # Format headers nicely for display
        response_data['headers'] = json.dumps(dict(resp.headers), indent=2)
        # Try to decode body, fall back to raw bytes representation if needed
        try:
            response_data['body'] = resp.text
        except Exception:
             response_data['body'] = str(resp.content) # Show raw bytes if decode fails


    except requests.exceptions.Timeout:
        response_data['error'] = 'Request timed out.'
    except requests.exceptions.ConnectionError:
        response_data['error'] = 'Could not connect to the specified URL.'
    except requests.exceptions.RequestException as e:
        response_data['error'] = f'An error occurred: {e}'
        app.logger.error(f"Request Exception: {e}")
    except Exception as e:
        # Catch unexpected errors during request processing
        response_data['error'] = f'An unexpected error occurred: {e}'
        app.logger.error(f"Unexpected Exception: {e}", exc_info=True)


    # Render the page again, passing the response data and original form data
    return render_template('index.html', response=response_data, form_data=request.form)

if __name__ == '__main__':
    # Run on 0.0.0.0 to be accessible within the EC2 instance's network
    # Port 5000 is common for Flask development
    # Set debug=False for any deployment, even restricted ones. Use True only for active development.
    app.run(host='0.0.0.0', port=5000, debug=True) # Set debug=False when not actively developing!
