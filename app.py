from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

agendamentos = []


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/agendar", methods=["POST"])
def agendar():

    dados = request.json

    agendamentos.append(dados)

    return jsonify({"ok": True})


@app.route("/lista")
def lista():

    return jsonify(agendamentos)


if __name__ == "__main__":
    app.run()                                                                                                                                                                                                                                                                                                                                                                                                                                                                               