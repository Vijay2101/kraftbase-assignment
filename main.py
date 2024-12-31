from fastapi import FastAPI, HTTPException, Depends, Query, status, Request
from starlette.middleware.sessions import SessionMiddleware
from sqlalchemy.orm import Session, joinedload
from database import SessionLocal, engine
from models import Base, User, Form, Field, Submission
from pydantic import BaseModel, EmailStr
from typing import List, Optional, Annotated, Union
from datetime import datetime, timedelta
import jwt
from passlib.context import CryptContext
import uuid
import re

Base.metadata.create_all(bind=engine)

app = FastAPI()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_dependency = Annotated[Session, Depends(get_db)]

SECRET_KEY = "secret"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Session Middleware
app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,  
    session_cookie="session_id",
    max_age=3600  
)

def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def validate_password(password: str):
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters long")
    if not re.search(r"\d", password):  
        raise HTTPException(status_code=400, detail="Password must contain at least one number")
    if not re.search(r"[A-Za-z]", password):  
        raise HTTPException(status_code=400, detail="Password must contain at least one letter")
    return password

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now() + expires_delta
    else:
        expire = datetime.now() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Authentication Routes
class UserCreate(BaseModel):
    username: str
    email: EmailStr  
    password: str  

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.password = validate_password(self.password)

@app.post("/auth/register")
def register(user: UserCreate, db: db_dependency):
    existing_user = db.query(User).filter(User.email == user.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    hashed_password = get_password_hash(user.password)
    db_user = User(username=user.username, email=user.email, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return {"msg": "User registered successfully"}

class UserLogin(BaseModel):
    email: EmailStr
    password: str

# Login Route
@app.post("/auth/login")
def login(user: UserLogin, request: Request, db: db_dependency):

    if len(user.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters long")
    
    db_user = db.query(User).filter(User.email == user.email).first()
    if not db_user or not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Generate session ID and store user info in the session
    session_id = str(uuid.uuid4())
    request.session["user_id"] = db_user.id
    request.session["email"] = db_user.email
    request.session["session_id"] = session_id
    
    return {"msg": "Login successful"}

@app.post("/auth/logout")
def logout(request: Request):
    request.session.clear()
    return {"msg": "User logged out successfully"}

# Form Management Routes
class FieldCreate(BaseModel):
    field_id: str
    type: str
    label: str
    required: bool

class FormCreate(BaseModel):
    title: str
    description: str
    fields: List[FieldCreate]

@app.post("/forms/create")
def create_form(form: FormCreate, db: db_dependency):
    db_form = Form(title=form.title, description=form.description)
    db.add(db_form)
    db.commit()
    db.refresh(db_form)
    for field in form.fields:
        db_field = Field(form_id=db_form.id, field_id=field.field_id, type=field.type, label=field.label, required=field.required)
        db.add(db_field)
    db.commit()
    return {"msg": "Form created successfully"}

@app.delete("/forms/delete/{form_id}")
def delete_form(form_id: int, db: db_dependency):
    db_form = db.query(Form).filter(Form.id == form_id).first()
    if not db_form:
        raise HTTPException(status_code=404, detail="Form not found")
    db.delete(db_form)
    db.commit()
    return {"msg": "Form deleted successfully"}

@app.get("/forms/")
def get_forms(db: db_dependency):
    forms = db.query(Form).options(joinedload(Form.fields)).all()
    return [
        {
            "form_id": form.id,
            "title": form.title,
            "description": form.description,
            "fields": [
                {
                    "field_id": field.field_id,
                    "type": field.type,
                    "label": field.label,
                    "required": field.required
                }
                for field in form.fields
            ]
        }
        for form in forms
    ]

@app.get("/forms/{form_id}")
def get_form(form_id: int, db: db_dependency):
    # Query the form by its ID and eagerly load the associated fields
    form = db.query(Form).options(joinedload(Form.fields)).filter(Form.id == form_id).first()

    # If the form is not found, raise a 404 error
    if not form:
        raise HTTPException(status_code=404, detail="Form not found")

    # Return the form details along with its fields
    return {
        "form_id": form.id,
        "title": form.title,
        "description": form.description,
        "fields": [
            {
                "field_id": field.field_id,
                "type": field.type,
                "label": field.label,
                "required": field.required
            }
            for field in form.fields
        ]
    }

class SubmissionResponse(BaseModel):
    field_id: str
    value: Union[str, int, bool] 

class SubmissionCreate(BaseModel):
    responses: List[SubmissionResponse]


@app.post("/forms/submit/{form_id}")
def submit_form(form_id: int, submission: SubmissionCreate, db: db_dependency):

    db_fields = db.query(Field).filter(Field.form_id == form_id).all()
    if not db_fields:
        raise HTTPException(status_code=404, detail="Form not found")

    field_map = {field.field_id: field for field in db_fields}

    submission_data = {}

    provided_fields = {response.field_id for response in submission.responses}

    # Check for missing required fields
    for field in db_fields:
        if field.required and field.field_id not in provided_fields:
            raise HTTPException(
                status_code=400,
                detail=f"Missing required field: {field.field_id}"
            )

    # Validate responses based on field type
    for response in submission.responses:
        if response.field_id not in field_map:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid field_id: {response.field_id}"
            )
        
        field = field_map[response.field_id]
        expected_type = field.type

        if expected_type == "string" and not isinstance(response.value, str):
            raise HTTPException(
                status_code=400,
                detail=f"Field {response.field_id} expects a string."
            )
        elif expected_type == "number" and not isinstance(response.value, (int, float)):
            raise HTTPException(
                status_code=400,
                detail=f"Field {response.field_id} expects a number."
            )
        elif expected_type == "boolean" and not isinstance(response.value, bool):
            raise HTTPException(
                status_code=400,
                detail=f"Field {response.field_id} expects a boolean."
            )

        submission_data[response.field_id] = response.value

    db_submission = Submission(form_id=form_id, data=str(submission_data))
    db.add(db_submission)
    db.commit()
    db.refresh(db_submission)

    return {"msg": "Form submitted successfully"}


@app.get("/forms/submissions/{form_id}")
def get_submissions(form_id: int,  db: db_dependency, page: int = 1, limit: int = 10):
    skip = (page - 1) * limit
    submissions = db.query(Submission).filter(Submission.form_id == form_id).offset(skip).limit(limit).all()
    submissions_data = list(
        map(
            lambda submission: {
                key: value for key, value in submission.__dict__.items()
                if key != "form_id"
            },
            submissions
        )
    )
    total_count = db.query(Submission).filter(Submission.form_id == form_id).count()
    return {"total_count": total_count, "page": page, "limit": limit, "submissions": submissions_data}
