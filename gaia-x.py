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
secret = os.getenv("API_SECRET", None)
client = OpenAI()

def basic_auth(username, password):
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode(
        "ascii"
    )
    return f"Basic {token}"

def generate_answer(question, context):

    messages=[
    ]
    # Build messages collection using the context
    # role 'agent' and 'bot' are considered as assistant input, role 'user' is user, role 'system' is ignored
    adviser_lang = None
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
            if content.startswith('adviser_lang='):
                adviser_lang = content[len('adviser_lang='):]
    messages.append({"role": "user", "content": question})
    if adviser_user_name:
        messages.insert(0, {"role": "system", "content": f"You are {adviser_user_name}, a helpfull assistant."})
    else:
        messages.insert(0, {"role": "system", "content": "You are a helpful assistant."})

    completion = client.chat.completions.create(
        temperature=0,
        model="gpt-3.5-turbo",
        messages=[
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": question}
        ]
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
    suggestion_id: int | None
    status: str
    answer: str | None = None

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
    if token_company_id is None:
        raise Exception("Invalid company_id")
    return token_company_id

app = FastAPI()

@app.post("/suggest-answer")
def suggest_answer(
    suggest_request: SuggestRequest,
    response: Response,
    authorization: Annotated[str | None, Header()] = None
):
    try:
        company_id = check_authorization(authorization)
        suggest_id = randint(0,1000000)
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

if __name__ == "__main__":
    logging.info("Start Chat")
    uvicorn.run(app, host="0.0.0.0", port=8080)

