from sqlalchemy import create_engine

DATABASE_URL = "mysql+pymysql://root:@localhost:3306/task1"

try:
    engine = create_engine(DATABASE_URL)
    connection = engine.connect()
    print("Connection successful!")
    connection.close()
except Exception as e:
    print(f"Connection failed: {e}")