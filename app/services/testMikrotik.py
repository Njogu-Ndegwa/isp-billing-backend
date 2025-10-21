from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from librouteros import connect

app = FastAPI()

def get_api():
    return connect(
        username='admin',
        password='Developer12@.',
        host='10.0.0.10',
        port=8728
    )

class UserRequest(BaseModel):
    name: str
    password: str

@app.post("/users")
def add_user(user: UserRequest):
    try:
        api = get_api()
        api.path("user").add(name=user.name, password=user.password, group="full")
        return {"message": f"User {user.name} added successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/users")
def list_users():
    try:
        api = get_api()
        return [u for u in get_api().path("user")]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/users/{name}")
def delete_user(name: str):
    try:
        api = get_api()
        for u in api.path("user"):
            if u.get("name") == name:
                api.path("user").remove(id=u[".id"])
                return {"message": f"User {name} deleted"}
        raise HTTPException(status_code=404, detail="User not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8008, reload=False)