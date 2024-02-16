"""
Sample implementation for AI suggestion generation.
"""
import jwt
import os
import logging
import logging
import threading
import base64
import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, Response, Header, status
from typing import List, Annotated
from pydantic import BaseModel, Field
from datetime import datetime
from random import randint
from openai import OpenAI

logging.basicConfig(level=logging.DEBUG)

load_dotenv(override=True)
public_key = os.getenv("PUBLIC_KEY", None)
api_url = os.getenv("API_URL", "https://api.alcmeon.com/ai/suggest-answer")
api_bot_url = os.getenv("API_BOT_URL", "https://api.alcmeon.com/ai/answer")
secret = os.getenv("API_SECRET", None)
default_company_id = os.getenv("COMPANY_ID", None)
bot_secret = os.getenv("BOT_API_KEY", None)
client = OpenAI()
use_context = os.getenv("USE_CONTEXT", False)

def basic_auth(username, password):
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode(
        "ascii"
    )
    return f"Basic {token}"


def build_messages_from_context(context):
    messages=[
    ]
    # Build messages collection using the context
    # role 'agent' and 'bot' are considered as assistant input, role 'user' is user, role 'system' is ignored
    adviser_user_name = None
    for item in context:
        content = item.content
        if item.role in ['adviser', 'bot'] and content:
            messages.append({"role": 'assistant', "content": content})
        elif item.role in ['user']  and content:
            messages.append({"role": 'user', "content": content})
        elif item.role in ['system']:
            if content.startswith('adviser_user_name='):
                adviser_user_name = content[len('adviser_user_name='):]
    system_content =  "You are a helpful assistant."
    if adviser_user_name:
        system_content += f" Your name is {adviser_user_name}"
    messages.insert(0, {"role": "system", "content": system_content})
        
    return messages
    
def generate_answer(question, context):

    if use_context and isinstance(context, list):
        messages = build_messages_from_context(context)
    else:
        messages=[
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": question}
        ]
    print(messages)
    completion = client.chat.completions.create(
        temperature=0,
        model="gpt-3.5-turbo",
        messages=messages
    )
    return completion.choices[0].message.content

def generate_suggestion(company_id:str, webhook_token:str, question:str, context:list, id:int):
    import requests
    try:
        print(f"Thread {webhook_token}: starting with {question}")
        created_at = datetime.now()
        error = None
        message = None
        try:
            message= generate_answer(question, context)
            print(message)
        except Exception as e:
            error=str(e)
            print(error)
        finished_at = datetime.now()
        headers = {
            "content-type": "application/json",
            "X-JWT": webhook_token,
            "Authorization": basic_auth(str(company_id), secret),
        }
        if error:
            suggest_answer = {
                    "id": id,
                    "error": error,
                    "status": 'failed',
                    "created_at": created_at.isoformat(),
                    "finished_at": finished_at.isoformat(),
                }
        else:
            suggest_answer = {
                    "id": id,
                    "answer": message,
                    "status": 'finished',
                    "created_at": created_at.isoformat(),
                    "finished_at": finished_at.isoformat(),
                }
        payload = {
            "suggest_answer": suggest_answer
        }
        response = requests.post(api_url, json=payload, headers=headers)
        print(f"Response '{response.text}' to post/{payload}")

    except Exception as e:
        print(e)

SUGGEST_TRANSFER_TO_AGENT = 'suggestContactEscalation'
MUST_TRANSFER_TO_AGENT = 'mustContactEscalation'
INVALID_SCOPE_TO_ANSWER = 'EndConversation'

def compute_code(question, answer):
    """ Compute code according to question and answer. As a sample we generate random answer """
    print(f"question={question}\nanswer={answer}")
    r = randint(0, 3)
    return [None, SUGGEST_TRANSFER_TO_AGENT, MUST_TRANSFER_TO_AGENT, INVALID_SCOPE_TO_ANSWER][r]


def generate_bot_answer(company_id:str, jwt:str, query:str, context:str):
    import requests
    try:
        print(f"Thread {jwt}: starting with {query}")
        error = None
        message = None
        code = None
        try:
            message= generate_answer(query, context)
            code = compute_code(query, message)
            print(message)
        except Exception as e:
            error=str(e)
            print(error)
        headers = {
            "content-type": "application/json",
            "X-JWT": jwt,
            "Authorization": basic_auth(str(company_id), secret),
        }
        message_payload = None
        error_payload = None
        if error:
            # If an error occurs, we send error messages for debugging purpose, and ask that conversation is transfered to an agent
            error_payload = {
                    "code": "responseGenerationError",
                    "details": error,
                }
            message_payload = {
                    "id": "",
                    "content": "",
                    "code": "mustContactEscalation",
                }
        else:
            # Send message directly to user
            message_payload = {
                    "id": str(randint(0,1000000)),
                    "content": message,
                    "code": code,
                }
        payload = {
            "message": message_payload,
            "error": error_payload,
        }
        response = requests.post(api_bot_url, json=payload, headers=headers)
        print(f"Response '{response.text}' to post/{payload}")

    except Exception as e:
        print(e)


class ContextItem(BaseModel):
    role: str
    content: str
    date: datetime | None = None

class SuggestRequest(BaseModel):
    version: str
    question: str
    context: List[ContextItem] | None = None
    webhook_token: str

class SuggestStats(BaseModel):
    version: str
    question: str
    context: List[ContextItem] | None = None
    suggestion: str
    suggestion_id: str | None
    status: str
    answer: str | None = None

class BotRequest(BaseModel):
    query: str
    context: str | None = None
    jwt: str

def check_authorization(authorization: str):
    if authorization is None :
        raise Exception("No authorization")

    if not authorization.startswith('Bearer '):
        raise Exception("Authorization not valid")

    token = authorization[7:]

    try:
        data = jwt.decode(jwt=token, key=public_key, algorithms=["RS256"])
    except jwt.exceptions.ExpiredSignatureError:
        raise Exception("Expired token")
    except Exception:
        raise Exception("Invalid token")

    token_company_id = data.get('company_id')
    if token_company_id is None or token_company_id != default_company_id:
        raise Exception("Invalid company_id")
    return token_company_id

def check_api_key(api_key: str):
    if bot_secret != api_key:
        raise Exception("Invalid token")
    return default_company_id

app = FastAPI()

@app.post("/suggest-answer")
def suggest_answer(
    suggest_request: SuggestRequest,
    response: Response,
    authorization: Annotated[str | None, Header()] = None
):
    try:
        company_id = check_authorization(authorization)
        suggest_id = str(randint(0,1000000))
        x = threading.Thread(
            target=generate_suggestion,
            args=(
                company_id,
                suggest_request.webhook_token,
                suggest_request.question,
                suggest_request.context,
                suggest_id,
            ),
        )
        x.start()
        return {
            "id": suggest_id,
            "status": 'started',
        }
    except Exception as e:
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return {
            "detail": {},
            "message": str(e)
        }


@app.post("/suggest-stats")
def suggest_stats(
    suggest_stats: SuggestStats,
    response: Response,
    authorization: Annotated[str | None, Header()] = None
):
    try:
        company_id = check_authorization(authorization)
        print(f"{company_id}, question='{suggest_stats.question}', suggestion[{suggest_stats.suggestion_id}]='{suggest_stats.suggestion}', status={suggest_stats.status}, answer='{suggest_stats.answer}'")
        return "ok"
    
    except Exception as e:
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return {
            "detail": {},
            "message": str(e)
        }


@app.post("/bot/")
def handle_bot(
    bot_request: BotRequest,
    response: Response,
    apiKey: Annotated[str | None, Header()] = None
):
    try:
        company_id = check_api_key(apiKey)
        x = threading.Thread(
            target=generate_bot_answer,
            args=(
                company_id,
                bot_request.jwt,
                bot_request.query,
                bot_request.context,
            ),
        )
        x.start()
        return {
            "status": 'Acknowledged',
        }
    except Exception as e:
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return {
            "errorId": 401,
            "errorDescription": str(e)
        }
    

if __name__ == "__main__":
    logging.info("Start Chat")
    uvicorn.run(app, host="0.0.0.0", port=8080)

