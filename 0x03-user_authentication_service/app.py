#!/usr/bin/env python3
"""API Routes for Authentication Service"""
from flask import Flask, jsonify, request, make_response, abort
from auth import Auth

app = Flask(__name__)

AUTH = Auth()

@app.route("/", methods=["GET"])
def welcome():
    return jsonify({"message": "Bienvenue"})

@app.route("/users", methods=["POST"])
def users():
    try:
        email = request.form.get("email")
        password = request.form.get("password")

        user = AUTH.register_user(email, password)
        return jsonify({"email": user.email, "message": "user created"})

    except ValueError as err:
        return jsonify({"message": "email already registered"}), 400

@app.route("/sessions", methods=["POST"])
def login():
    try:
        email = request.form.get("email")
        password = request.form.get("password")

        if AUTH.valid_login(email, password):
            session_id = AUTH.create_session(email)
            response = jsonify({"email": email, "message": "logged in"})
            response.set_cookie("session_id", session_id)
            return response
        else:
            abort(401)

    except:
        abort(401)

@app.route("/sessions", methods=["DELETE"])
def log_out():
    session_id = request.cookies.get("session_id")

    user = AUTH.get_user_from_session_id(session_id)
    if user:
        AUTH.destroy_session(user.id)
        return redirect("/")
    else:
        abort(403)

@app.route('/profile', methods=['GET'])
def profile() -> str:
    """
    Retrieve user profile information based on the session ID.
    
    This endpoint expects a session ID cookie. It uses the session ID to find
    the corresponding user. If the user exists, it responds with a 200 HTTP status
    and a JSON payload containing the user's email. If the user does not exist, a
    403 HTTP status is returned.

    Returns:
        JSON response with user's email and HTTP status code.
    """
    session_id = request.cookies.get("session_id", None)

    if session_id is None:
        abort(403)

    user = AUTH.get_user_from_session_id(session_id)

    if user is None:
        abort(403)

    profile_data = {
            "email": user.email
        }
    return jsonify(profile_data), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")

