import sqlite3

def init_db():
    connection = sqlite3.connect('database.db')
    cursor = connection.cursor()

    # Open and read the file as a single buffer
    with open('schema.sql', 'r') as schema_file:
        schema_script = schema_file.read()
    
    # Execute the schema script
    cursor.executescript(schema_script)
    
    # Commit changes and close the connection
    connection.commit()
    connection.close()

if __name__ == '__main__':
    init_db()
    print("Database initialized.")
