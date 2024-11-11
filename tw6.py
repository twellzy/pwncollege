import requests
import json

url = 'http://challenge.localhost/info?user=1'

# Define the session cookie
session_cookie = 'eyJ1c2VyIjoxfQ.Zp2rqw.nkOkIwVOnIPjFouCA4tyHDsazPk'

# Create a session object
session = requests.Session()

# Set the cookie in the session
session.cookies.set('session', session_cookie)

# Send a GET request
response = session.get(url)

# Print the response text
print(response.text)
