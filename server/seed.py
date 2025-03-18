import sqlite3

def main():
    conn = sqlite3.connect('main.db')
    cursor = conn.cursor()
    cursor.execute("PRAGMA journal_mode=WAL;")

    cursor.execute(""" 
    CREATE TABLE IF NOT EXISTS USERS (
        ID INTEGER PRIMARY KEY,
        PhoneHash TEXT,
        Name TEXT,
        EdPublic TEXT
    )
    """)

if __name__ == "__main__":
    main()