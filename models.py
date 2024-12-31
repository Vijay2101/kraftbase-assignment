from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from database import Base
from datetime import datetime

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)

class Form(Base):
    __tablename__ = "forms"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String)
    description = Column(String)
    fields = relationship("Field", back_populates="form", cascade="all, delete-orphan")
    submissions = relationship("Submission", back_populates="form", cascade="all, delete")
    
class Field(Base):
    __tablename__ = "fields"
    id = Column(Integer, primary_key=True, index=True)
    form_id = Column(Integer, ForeignKey("forms.id"))
    field_id = Column(String)
    type = Column(String)
    label = Column(String)
    required = Column(Boolean)
    form = relationship("Form", back_populates="fields")

class Submission(Base):
    __tablename__ = "submissions"
    submission_id = Column(Integer, primary_key=True, index=True)
    form_id = Column(Integer, ForeignKey("forms.id"))
    submitted_at = Column(DateTime, default=datetime.now)
    data = Column(String)
    form = relationship("Form", back_populates="submissions")