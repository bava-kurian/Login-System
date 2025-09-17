from sqlalchemy import create_engine, inspect

DATABASE_URL = "mysql+pymysql://root:@localhost:3306/task1"

try:
    # Create the engine and connect to the database
    engine = create_engine(DATABASE_URL)
    connection = engine.connect()
    print("Connection successful!")

    # Use SQLAlchemy's inspector to fetch the tables
    inspector = inspect(engine)
    tables = inspector.get_table_names()

    if tables:
        print("Tables in the database:")
        for table in tables:
            print(f"- {table}")
    else:
        print("No tables found in the database.")

    # Close the connection
    connection.close()
except Exception as e:
    print(f"Connection failed: {e}")