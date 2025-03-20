import sqlite3
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import declarative_base, sessionmaker

engine = create_engine("sqlite:///main.db", echo=True)
Base = declarative_base()

class User(Base):
    __tablename__ = 'USERS'
    id = Column(Integer, primary_key=True, autoincrement=True)
    phonehash = Column(String, nullable=False)
    name = Column(String, nullable=False)
    edpublic = Column(String, nullable=False)

def create_db():
    Base.metadata.create_all(engine)

if __name__ == "__main__":
    create_db()