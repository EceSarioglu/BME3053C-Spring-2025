from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import List, Optional
from jose import JWTError, jwt  # Changed from import jwt
from datetime import datetime, timedelta

app = FastAPI(title="Patient Management System")

# Secret key for JWT token
SECRET_KEY = "your-secret-key-here"
ALGORITHM = "HS256"

# Mock database
patients_db = {}
users_db = {
    "admin": {
        "username": "admin",
        "hashed_password": "secretpassword",
        "is_active": True
    }
}

# Models
class Patient(BaseModel):
    name: str
    age: int
    condition: str
    notes: Optional[str] = None

class PatientResponse(Patient):
    id: int

class User(BaseModel):
    username: str
    is_active: bool = True

# Authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=30)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401)
    except jwt.JWTError:
        raise HTTPException(status_code=401)
    user = users_db.get(username)
    if user is None:
        raise HTTPException(status_code=401)
    return user

# Authentication endpoint
@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = users_db.get(form_data.username)
    if not user or form_data.password != user["hashed_password"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )
    access_token = create_access_token({"sub": user["username"]})
    return {"access_token": access_token, "token_type": "bearer"}

# Patient endpoints
@app.post("/patients/", response_model=PatientResponse)
async def create_patient(patient: Patient, current_user: User = Depends(get_current_user)):
    patient_id = len(patients_db) + 1
    patients_db[patient_id] = patient.dict()
    return {**patient.dict(), "id": patient_id}

@app.get("/patients/", response_model=List[PatientResponse])
async def read_patients(current_user: User = Depends(get_current_user)):
    return [{"id": k, **v} for k, v in patients_db.items()]

@app.get("/patients/{patient_id}", response_model=PatientResponse)
async def read_patient(patient_id: int, current_user: User = Depends(get_current_user)):
    if patient_id not in patients_db:
        raise HTTPException(status_code=404, detail="Patient not found")
    return {"id": patient_id, **patients_db[patient_id]}

@app.put("/patients/{patient_id}", response_model=PatientResponse)
async def update_patient(
    patient_id: int, 
    patient: Patient, 
    current_user: User = Depends(get_current_user)
):
    if patient_id not in patients_db:
        raise HTTPException(status_code=404, detail="Patient not found")
    patients_db[patient_id] = patient.dict()
    return {"id": patient_id, **patient.dict()}

@app.delete("/patients/{patient_id}")
async def delete_patient(patient_id: int, current_user: User = Depends(get_current_user)):
    if patient_id not in patients_db:
        raise HTTPException(status_code=404, detail="Patient not found")
    del patients_db[patient_id]
    return {"message": "Patient deleted successfully"}