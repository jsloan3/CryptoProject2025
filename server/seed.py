import datetime
import sqlite3
from sqlalchemy import DateTime, create_engine, Column, Integer, String, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
import json

engine = create_engine("sqlite:///main.db", echo=True)
Base = declarative_base()

class User(Base):
    __tablename__ = 'USERS'
    id = Column(Integer, primary_key=True, autoincrement=True)
    phonehash = Column(String, nullable=False)
    name = Column(String, nullable=False)
    edpublic = Column(String, nullable=False)
    messages = relationship("Message", foreign_keys="Message.recipient", back_populates="recipient_rel")

class Message(Base):
    __tablename__ = 'MESSAGES'
    id = Column(Integer, primary_key=True, autoincrement=True)
    sender = Column(Integer, ForeignKey('USERS.id'))
    recipient = Column(Integer, ForeignKey('USERS.id'))
    data = Column(String, nullable=False)
    sender_pub = Column(String)
    recipient_pub = Column(String)
    time = Column(DateTime, default=datetime.datetime.now())

    sender_rel = relationship("User", foreign_keys=[sender])
    recipient_rel = relationship("User", foreign_keys=[recipient], back_populates="messages")

    def to_dict(self):
        return {column.name: getattr(self, column.name) for column in self.__table__.columns}

def create_db():
    Base.metadata.create_all(engine)

if __name__ == "__main__":
    create_db()