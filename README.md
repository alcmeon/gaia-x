# Gaia-x

Gaia-x is a sample server that provide suggestion in Alcméon processing page.

### Installing dependencies
It's better to create a local .venv to avoid collision, due to number of dependecies in langchain

```
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### How to use
You will need:
- a OpenAI API key.
- a ngrok account (free or not) with a domain to setup a public HTTPS frontal for your server. This url must be used to create a Gaia environnement in alcmeon.
- an active application in your Alcméon account with AI permission (and its secret)
- The public key of the webhook created in Alcméon with your server url.

Create a .env file at the root of the project

```
OPENAI_API_KEY=" your openai key  "
PUBLIC_KEY="
-----BEGIN PUBLIC KEY-----
The public key for your web hook
-----END PUBLIC KEY-----
"
API_SECRET=" the secret of the application with AI permission "
```
You can also add a **API_URL** if you want to change the default value of **https://api.alcmeon.com/ai/suggest-answer**

Then run the gaia-x server with:
```
source .venv/bin/activate
python gaia-x.py
```

And give access using ngrok
```
ngrok http --domain=yourdomain.ngrok... 8080
```

Using suggestion in Alcméon processing page should propose an answer generated by OpenAI.
