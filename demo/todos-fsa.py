#
# FlaskSimpleAuth version of Flask-RESTful TODO application
# https://flask-restful.readthedocs.io/en/latest/quickstart.html
#
from FlaskSimpleAuth import Flask, abort

app = Flask("todo")
app.config.from_env("TODO_CONFIG")

TODOS = {
    "todo1": {"task": "build an API"},
    "todo2": {"task": "?????"},
    "todo3": {"task": "profit!"},
}


def abort_if_todo_doesnt_exist(tid):
    if tid not in TODOS:
        abort(404, message=f"Todo {tid} doesn't exist")


@app.get("/todos/<tid>", authorize="ANY")
def get_todos_tid(tid: str):
    abort_if_todo_doesnt_exist(tid)
    return TODOS[tid], 200


@app.put("/todos/<tid>", authorize="ANY")
def put_todos_tid(tid: str, task: str):
    abort_if_todo_doesnt_exist(tid)
    TODOS[tid] = task
    return "", 201


@app.delete("/todos/<tid>", authorize="ANY")
def delete_todos_tid(tid: str):
    abort_if_todo_doesnt_exist(tid)
    del TODOS[tid]
    return "", 204


@app.get("/todos", authorize="ANY")
def get_todos():
    return TODOS


@app.post("/todos", authorize="ANY")
def post_todos(task: str):
    # FIXME complexity!
    i = int(max(TODOS.keys()).lstrip("todo")) + 1
    tid = f"todo{i}"
    TODOS[tid] = {"task": task}
    return TODOS[tid], 201


# NOTE not really needed
if __name__ == "__main__":
    app.run(debug=True)
