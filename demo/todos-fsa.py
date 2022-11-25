#
# FlaskSimpleAuth version of Flask-RESTful TODO application
# https://flask-restful.readthedocs.io/en/latest/quickstart.html
#
from FlaskSimpleAuth import Flask, jsonify as json

app = Flask("todos")
app.config.from_envvar("TODOS_CONFIG")

TODOS = {
    "todo1": {"task": "build an API"},
    "todo2": {"task": "?????"},
    "todo3": {"task": "profit!"},
}

@app.object_perms("todos")
def check_todos_access(login: str, tid: str, mode = None):
    # NOTE returning None triggers a 404
    return True if tid in TODOS else None


@app.get("/todos/<tid>", authorize=("todos",))
def get_todos_tid(tid: str):
    return TODOS[tid], 200


@app.put("/todos/<tid>", authorize=("todos",))
def put_todos_tid(tid: str, task: str):
    TODOS[tid] = {"task": task}
    return "", 204


@app.delete("/todos/<tid>", authorize=("todos",))
def delete_todos_tid(tid: str):
    del TODOS[tid]
    return "", 204


@app.get("/todos", authorize="ANY")
def get_todos():
    return TODOS, 200


@app.post("/todos", authorize="ANY")
def post_todos(task: str):
    # FIXME complexity!
    i = int(max(TODOS.keys()).lstrip("todo")) + 1
    tid = f"todo{i}"
    TODOS[tid] = {"task": task}
    return json(tid), 201  # NOTE return the created key


# NOTE not really needed
if __name__ == "__main__":
    app.run(debug=True)
