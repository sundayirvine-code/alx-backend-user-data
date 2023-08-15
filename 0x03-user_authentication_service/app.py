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

@app.route("/reset_password", methods=["POST"])
def get_reset_password_token():
    """
    Generate a reset password token for the user based on their email.

    This endpoint expects form data with the "email" field. If the email is
    registered, it generates a reset token and responds with a 200 HTTP status
    and a JSON payload containing the user's email and the reset token.
    If the email is not registered, a 403 HTTP status is returned.

    Returns:
        JSON response with user's email, reset token, and HTTP status code.
    """
    email = request.form.get("email")

    try:
        reset_token = AUTH.get_reset_password_token(email)
        response_data = {
            "email": email,
            "reset_token": reset_token
        }
        return jsonify(response_data), 200
    except ValueError as err:
        abort(403)

@app.route("/reset_password", methods=["PUT"])
def update_password():
    """
    Update the user's password based on the reset token.

    This endpoint expects form data with the "email", "reset_token", and "new_password"
    fields. It attempts to update the user's password using the reset token.
    If the token is invalid, a 403 HTTP status is returned.
    If the token is valid, a 200 HTTP status is returned along with a JSON payload
    containing the user's email and a "Password updated" message.

    Returns:
        JSON response with user's email, message, and HTTP status code.
    """
    email = request.form.get("email")
    reset_token = request.form.get("reset_token")
    new_password = request.form.get("new_password")

    try:
        AUTH.update_password(reset_token, new_password)
        response_data = {
            "email": email,
            "message": "Password updated"
        }
        return jsonify(response_data), 200
    except ValueError as err:
        abort(403)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")

