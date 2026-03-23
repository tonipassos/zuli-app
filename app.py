from flask import Flask, render_template, request, jsonify
import sqlite3

app = Flask(__name__)


def criar_db():

    conn = sqlite3.connect("usuarios.db")
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS usuarios(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        usuario TEXT,
        senha TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS agendamentos(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        data TEXT,
        hora TEXT
    )
    """)

    conn.commit()
    conn.close()


criar_db()



@app.route("/")
def home():
    return render_template("index.html")



@app.route("/cadastro", methods=["POST"])
def cadastro():

    dados = request.json

    usuario = dados["usuario"]
    senha = dados["senha"]

    conn = sqlite3.connect("usuarios.db")
    c = conn.cursor()

    c.execute(
        "INSERT INTO usuarios(usuario,senha) VALUES (?,?)",
        (usuario, senha)
    )

    conn.commit()
    conn.close()

    return jsonify({"status":"cadastrado"})



@app.route("/login", methods=["POST"])
def login():

    dados = request.json

    usuario = dados["usuario"]
    senha = dados["senha"]

    conn = sqlite3.connect("usuarios.db")
    c = conn.cursor()

    c.execute(
        "SELECT * FROM usuarios WHERE usuario=? AND senha=?",
        (usuario, senha)
    )

    r = c.fetchone()

    conn.close()

    if r:
        return jsonify({"status":"ok"})
    else:
        return jsonify({"status":"erro"})



@app.route("/agendar", methods=["POST"])
def agendar():

    dados = request.json

    data = dados["data"]
    hora = dados["hora"]

    conn = sqlite3.connect("usuarios.db")
    c = conn.cursor()

    c.execute(
        "INSERT INTO agendamentos(data,hora) VALUES (?,?)",
        (data, hora)
    )

    conn.commit()
    conn.close()

    return jsonify({"status":"agendado"})



app.run(host="0.0.0.0", port=5000)
