import os
import jwt
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, g
from flask_cors import CORS
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from functools import wraps
from groq import Groq

from models import db, User, Conversation, Message

load_dotenv()

# ---------------------------------------------------------------------
# App Setup
# ---------------------------------------------------------------------
app = Flask(__name__)
CORS(app)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///chat.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)

with app.app_context():
    db.create_all()  # create tables

# ---------------------------------------------------------------------
# Auth + JWT
# ---------------------------------------------------------------------
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")
JWT_ALGO = "HS256"
JWT_EXPIRES_MINUTES = 60 * 24

def create_token(user_id, username):
    payload = {
        "user_id": user_id,
        "username": username,
        "exp": datetime.utcnow() + timedelta(minutes=JWT_EXPIRES_MINUTES),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)

def auth_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Unauthorized"}), 401

        token = auth.split(" ")[1]
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
            g.user_id = payload["user_id"]
            g.username = payload["username"]
        except Exception:
            return jsonify({"error": "Invalid or expired token"}), 401

        return f(*args, **kwargs)

    return wrapper

# ---------------------------------------------------------------------
# Groq AI
# ---------------------------------------------------------------------
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
client = Groq(api_key=GROQ_API_KEY)

def generate_ai_reply(user_message):
    try:
        response = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[
                {"role": "system", "content": "You are a friendly AI assistant."},
                {"role": "user", "content": user_message},
            ],
            max_tokens=150,
            temperature=0.7,
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        print("Groq error:", e)
        return "Sorry, I couldn't reach the AI service."

# ---------------------------------------------------------------------
# Authentication Routes
# ---------------------------------------------------------------------
@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    if not username or not password:
        return jsonify({"error": "username and password required"}), 400

    exists = User.query.filter_by(username=username).first()
    if exists:
        return jsonify({"error": "Username already taken"}), 400

    user = User(username=username, password_hash=generate_password_hash(password))
    db.session.add(user)
    db.session.commit()

    token = create_token(user.id, user.username)
    return jsonify({"message": "Registration successful", "token": token, "username": user.username})


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({"error": "Invalid username or password"}), 401

    token = create_token(user.id, user.username)
    return jsonify({"message": "Login successful", "token": token, "username": user.username})

# ---------------------------------------------------------------------
# Conversation Routes
# ---------------------------------------------------------------------
@app.route("/api/conversation", methods=["POST"])
@auth_required
def create_conversation():
    body = request.get_json() or {}
    title = body.get("title") or f"Chat {datetime.utcnow().isoformat()}"

    conv = Conversation(user_id=g.user_id, title=title)
    db.session.add(conv)
    db.session.commit()

    return jsonify({"id": conv.id, "title": conv.title})


@app.route("/api/conversations", methods=["GET"])
@auth_required
def list_conversations():
    convs = (
        Conversation.query.filter_by(user_id=g.user_id)
        .order_by(Conversation.updated_at.desc())
        .all()
    )
    result = []
    for c in convs:
        last = (
            Message.query.filter_by(conversation_id=c.id)
            .order_by(Message.created_at.desc())
            .first()
        )
        result.append(
            {
                "id": c.id,
                "title": c.title,
                "updated_at": c.updated_at.isoformat(),
                "lastMessageSnippet": (last.text[:140] + "...") if last else "",
            }
        )
    return jsonify(result)


@app.route("/api/conversation/<int:cid>", methods=["GET"])
@auth_required
def get_conversation(cid):
    conv = Conversation.query.filter_by(id=cid, user_id=g.user_id).first()
    if not conv:
        return jsonify({"error": "Conversation not found"}), 404

    msgs = [
        m.to_dict()
        for m in Message.query.filter_by(conversation_id=cid).order_by(Message.created_at.asc())
    ]

    return jsonify({"id": conv.id, "title": conv.title, "messages": msgs})

# ---------------------------------------------------------------------
# Messaging Route (AI Chat)
# ---------------------------------------------------------------------
@app.route("/api/conversation/<int:cid>/send", methods=["POST"])
@auth_required
def send_message(cid):
    conv = Conversation.query.filter_by(id=cid, user_id=g.user_id).first()
    if not conv:
        return jsonify({"error": "Conversation not found"}), 404

    data = request.get_json() or {}
    user_text = data.get("text", "").strip()

    if not user_text:
        return jsonify({"error": "Text cannot be empty"}), 400

    # Save user message
    user_msg = Message(
        conversation_id=cid,
        user_id=g.user_id,
        sender="user",
        text=user_text,
    )
    db.session.add(user_msg)
    db.session.commit()

    # AI reply
    ai_text = generate_ai_reply(user_text)

    ai_msg = Message(
        conversation_id=cid,
        sender="ai",
        text=ai_text,
    )
    db.session.add(ai_msg)
    conv.updated_at = datetime.utcnow()
    db.session.commit()

    return jsonify(
        {
            "messages": [user_msg.to_dict(), ai_msg.to_dict()],
            "conversationId": cid,
        }
    )

# ---------------------------------------------------------------------

@app.route("/", methods=["GET"])
def root():
    return "FuboticsAI Backend Running"

# ---------------------------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True)
