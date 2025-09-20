from flask import Flask, render_template, request, jsonify
import re

app = Flask(__name__)


def check_password_strength(password):
    length_error = len(password) < 8
    digit_error = re.search(r"\d", password) is None
    uppercase_error = re.search(r"[A-Z]", password) is None
    lowercase_error = re.search(r"[a-z]", password) is None
    symbol_error = re.search(r"[ @!#$%^&*()<>?/\\|}{~:]", password) is None

    score = 5 - sum([length_error, digit_error,
                    uppercase_error, lowercase_error, symbol_error])

    if score == 5:
        return "Strong"
    elif score >= 3:
        return "Medium"
    else:
        return "Weak"


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        password = request.form.get("password")
        strength = check_password_strength(password)
        return jsonify({"strength": strength})
    return render_template("index.html")


if __name__ == "__main__":
    app.run(debug=True)
