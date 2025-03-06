import sqlite3
from flask import Flask, render_template

app = Flask(__name__)

def get_database_connection():
    connection = sqlite3.connect('database.db')
    connection.row_factory = sqlite3.Row
    return connection