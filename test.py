import sqlite3

def login(username, password):
    connection = sqlite3.connect('test.db')
    cursor = connection.cursor()
    
    # Vulnerable SQL query
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}';"
    cursor.execute(query)
    user = cursor.fetchone()
    
    if user:
        print("Login successful!")
    else:
        print("Login failed.")
    
    connection.close()

# Example usage (user-supplied inputs could exploit this)
login("admin", "' OR '1'='1")
