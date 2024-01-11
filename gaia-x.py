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
from operator import itemgetter
from typing import List, Tuple, Annotated
from pydantic import BaseModel
from datetime import datetime
from random import randint
from openai import OpenAI


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
        {"role": "system", "content": "You are a helpful assistant."},
    ]
    role = "user"
    for str in context:
        messages.append({"role": role, "content": str})
    messages.append({"role": "user", "content": question})
    print(messages)
    completion = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": question}
        ]
    )

    return completion.choices[0].message.content

def generate_suggestion(company_id, webhook_token, question, context, id):
    import requests
    try:
        print(f"Thread {webhook_token}: starting with {question}")
        created_at = datetime.now()
        message= generate_answer(question, context)
        finished_at = datetime.now()
        print(message)
        headers = {
            "content-type": "application/json",
            "X-JWT": webhook_token,
            "Authorization": basic_auth(str(company_id), secret),
        }
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
        response = requests.post(url, json=payload, headers=headers)
        print(f"Respose '{response.text}' to post/{payload}")

    except Exception as e:
        print(e)



class SuggestRequest(BaseModel):
    question: str
    context: List[str] | None = None
    webhook_token: str

def check_authorization(authorization: str, company_id:int):
    error = "No authorization"
    if authorization is not None and authorization.startswith('Bearer '):
        token = authorization[7:]
        try:
            data = jwt.decode(jwt=token, key=public_key, algorithms=["RS256"])
            decoded_company_id = data.get('company_id')
            if decoded_company_id is not None and decoded_company_id == company_id:
                return None
            else:
                error = "Bad company id"
        except Exception:
            error = "Invalid token"
    return error

app = FastAPI()


@app.post("/{company_id}/api/v1/suggest-answer")
def suggest_answer(
    company_id: int,
    suggest_request: SuggestRequest,
    response: Response,
    authorization: Annotated[str | None, Header()] = None
):
    error = check_authorization(authorization, company_id)
    if error is None:
        suggest_id = randint(0,1000000)
        x = threading.Thread(
            target=generate_suggestion,
            args=(
                company_id,
                suggest_request.webhook_token,
                suggest_request.question,
                suggest_request.context,
                suggest_id
            ),
        )
        x.start()
        return {
            "id": suggest_id,
            "status": 'started',
        }
    else:
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return {
            "detail": {},
            "message": error
        }


if __name__ == "__main__":
    logging.info("Start Chat")
    uvicorn.run(app, host="0.0.0.0", port=8080)

