from flask import Flask, render_template

app = Flask(__name__)


@app.route("/")
def main() -> str:
    return render_template("layout.html")  # Change this to the actual html file.

@app.route('/contacts')
def contacts():
    return render_template('contacts.html')

if __name__ == "__main__":
    app.run(debug=True)
