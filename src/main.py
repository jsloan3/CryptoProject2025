from flask import Flask, render_template

app = Flask(__name__)


@app.route("/")
def main() -> str:
    return render_template("layout.html")  # Change this to the actual html file.


if __name__ == "__main__":
    app.run(debug=True)
