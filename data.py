import sqlite3

def create_database():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    # Create table
    c.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            name TEXT,
            password TEXT,
            phone_number TEXT CHECK(length(phone_number) = 8)
        )
    ''')

    # Insert some data
    users = [('John Doe', 'password1', '12345678'),
             ('Jane Doe', 'password2', '87654321'),
             ('Alice', 'password3', '11223344'),
             ('Bob', 'password4', '44332211')]
    c.executemany('INSERT INTO users (name, password, phone_number) VALUES (?, ?, ?)', users)

    # Save (commit) the changes and close the connection
    conn.commit()
    conn.close()

if __name__ == "__main__":
    create_database()