from flask import Flask, render_template, request, jsonify, session
from flask_cors import CORS
import os
import bcrypt
import psycopg2
import psycopg2.extras
from datetime import datetime
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "zuli-secret-2026")
CORS(app)

# ═══════════════════════════════════════════
# CONEXÃO COM BANCO DE DADOS
# Use PostgreSQL no Render (variável de ambiente)
# ═══════════════════════════════════════════
def get_db():
    conn = psycopg2.connect(
        os.environ.get("DATABASE_URL"),
        cursor_factory=psycopg2.extras.RealDictCursor
    )
    return conn

# ═══════════════════════════════════════════
# CRIAR TABELAS
# ═══════════════════════════════════════════
def criar_tabelas():
    conn = get_db()
    c = conn.cursor()

    # Usuários com senha criptografada
    c.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id SERIAL PRIMARY KEY,
            nome TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            senha TEXT NOT NULL,
            perfil TEXT DEFAULT 'cliente',
            telefone TEXT,
            cidade TEXT,
            criado_em TIMESTAMP DEFAULT NOW()
        )
    """)

    # Profissionais
    c.execute("""
        CREATE TABLE IF NOT EXISTS profissionais (
            id SERIAL PRIMARY KEY,
            nome TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            categoria TEXT,
            descricao TEXT,
            preco_minimo DECIMAL(10,2),
            avaliacao DECIMAL(3,2) DEFAULT 5.0,
            cidade TEXT,
            ativo BOOLEAN DEFAULT TRUE,
            aprovado BOOLEAN DEFAULT FALSE,
            criado_em TIMESTAMP DEFAULT NOW()
        )
    """)

    # Serviços dos profissionais
    c.execute("""
        CREATE TABLE IF NOT EXISTS servicos (
            id SERIAL PRIMARY KEY,
            profissional_id INTEGER REFERENCES profissionais(id),
            nome TEXT NOT NULL,
            duracao_min INTEGER,
            preco DECIMAL(10,2),
            ativo BOOLEAN DEFAULT TRUE
        )
    """)

    # Agendamentos
    c.execute("""
        CREATE TABLE IF NOT EXISTS agendamentos (
            id SERIAL PRIMARY KEY,
            cliente_id INTEGER REFERENCES usuarios(id),
            profissional_id INTEGER REFERENCES profissionais(id),
            servico TEXT NOT NULL,
            data DATE NOT NULL,
            horario TIME NOT NULL,
            valor DECIMAL(10,2),
            status TEXT DEFAULT 'pendente',
            criado_em TIMESTAMP DEFAULT NOW()
        )
    """)

    # Pagamentos
    c.execute("""
        CREATE TABLE IF NOT EXISTS pagamentos (
            id SERIAL PRIMARY KEY,
            agendamento_id INTEGER REFERENCES agendamentos(id),
            valor_total DECIMAL(10,2),
            taxa_zuli DECIMAL(10,2),
            valor_profissional DECIMAL(10,2),
            metodo TEXT,
            status TEXT DEFAULT 'pendente',
            mp_payment_id TEXT,
            criado_em TIMESTAMP DEFAULT NOW()
        )
    """)

    # Avaliações
    c.execute("""
        CREATE TABLE IF NOT EXISTS avaliacoes (
            id SERIAL PRIMARY KEY,
            cliente_id INTEGER REFERENCES usuarios(id),
            profissional_id INTEGER REFERENCES profissionais(id),
            agendamento_id INTEGER REFERENCES agendamentos(id),
            nota INTEGER CHECK (nota BETWEEN 1 AND 5),
            comentario TEXT,
            criado_em TIMESTAMP DEFAULT NOW()
        )
    """)

    conn.commit()
    conn.close()
    print("✅ Tabelas criadas com sucesso!")

# ═══════════════════════════════════════════
# DECORATOR — EXIGE LOGIN
# ═══════════════════════════════════════════
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "usuario_id" not in session:
            return jsonify({"status": "erro", "msg": "Faça login para continuar"}), 401
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get("perfil") != "admin":
            return jsonify({"status": "erro", "msg": "Acesso negado"}), 403
        return f(*args, **kwargs)
    return decorated

# ═══════════════════════════════════════════
# ROTA PRINCIPAL
# ═══════════════════════════════════════════
@app.route("/")
def home():
    return render_template("index.html")

# ═══════════════════════════════════════════
# AUTH — CADASTRO
# ═══════════════════════════════════════════
@app.route("/api/cadastro", methods=["POST"])
def cadastro():
    dados = request.json

    # Validações
    nome   = dados.get("nome", "").strip()
    email  = dados.get("email", "").strip().lower()
    senha  = dados.get("senha", "")
    perfil = dados.get("perfil", "cliente")

    if not nome or not email or not senha:
        return jsonify({"status": "erro", "msg": "Preencha todos os campos"}), 400

    if "@" not in email:
        return jsonify({"status": "erro", "msg": "E-mail inválido"}), 400

    if len(senha) < 6:
        return jsonify({"status": "erro", "msg": "Senha deve ter mínimo 6 caracteres"}), 400

    # Criptografar senha com bcrypt
    senha_hash = bcrypt.hashpw(senha.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    try:
        conn = get_db()
        c = conn.cursor()
        c.execute(
            "INSERT INTO usuarios (nome, email, senha, perfil) VALUES (%s, %s, %s, %s) RETURNING id",
            (nome, email, senha_hash, perfil)
        )
        usuario_id = c.fetchone()["id"]
        conn.commit()
        conn.close()

        # Salvar sessão
        session["usuario_id"] = usuario_id
        session["nome"]       = nome
        session["email"]      = email
        session["perfil"]     = perfil

        return jsonify({"status": "ok", "msg": "Conta criada!", "perfil": perfil})

    except psycopg2.errors.UniqueViolation:
        return jsonify({"status": "erro", "msg": "E-mail já cadastrado"}), 409
    except Exception as e:
        return jsonify({"status": "erro", "msg": str(e)}), 500

# ═══════════════════════════════════════════
# AUTH — LOGIN
# ═══════════════════════════════════════════
@app.route("/api/login", methods=["POST"])
def login():
    dados  = request.json
    email  = dados.get("email", "").strip().lower()
    senha  = dados.get("senha", "")

    if not email or not senha:
        return jsonify({"status": "erro", "msg": "Preencha e-mail e senha"}), 400

    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM usuarios WHERE email = %s", (email,))
        usuario = c.fetchone()
        conn.close()

        if not usuario:
            return jsonify({"status": "erro", "msg": "E-mail ou senha incorretos"}), 401

        # Verificar senha com bcrypt
        senha_correta = bcrypt.checkpw(senha.encode("utf-8"), usuario["senha"].encode("utf-8"))

        if not senha_correta:
            return jsonify({"status": "erro", "msg": "E-mail ou senha incorretos"}), 401

        # Salvar sessão
        session["usuario_id"] = usuario["id"]
        session["nome"]       = usuario["nome"]
        session["email"]      = usuario["email"]
        session["perfil"]     = usuario["perfil"]

        return jsonify({
            "status": "ok",
            "msg":    "Login realizado!",
            "nome":   usuario["nome"],
            "perfil": usuario["perfil"]
        })

    except Exception as e:
        return jsonify({"status": "erro", "msg": str(e)}), 500

# ═══════════════════════════════════════════
# AUTH — LOGOUT
# ═══════════════════════════════════════════
@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"status": "ok", "msg": "Saiu com sucesso"})

# ═══════════════════════════════════════════
# AUTH — SESSÃO ATUAL
# ═══════════════════════════════════════════
@app.route("/api/sessao")
def sessao():
    if "usuario_id" in session:
        return jsonify({
            "logado":  True,
            "nome":    session["nome"],
            "email":   session["email"],
            "perfil":  session["perfil"]
        })
    return jsonify({"logado": False})

# ═══════════════════════════════════════════
# PROFISSIONAIS — LISTAR
# ═══════════════════════════════════════════
@app.route("/api/profissionais")
def listar_profissionais():
    categoria = request.args.get("categoria")
    busca     = request.args.get("busca")

    try:
        conn = get_db()
        c = conn.cursor()

        query = "SELECT * FROM profissionais WHERE ativo = TRUE AND aprovado = TRUE"
        params = []

        if categoria:
            query += " AND categoria = %s"
            params.append(categoria)

        if busca:
            query += " AND (nome ILIKE %s OR descricao ILIKE %s OR cidade ILIKE %s)"
            params.extend([f"%{busca}%", f"%{busca}%", f"%{busca}%"])

        query += " ORDER BY avaliacao DESC"

        c.execute(query, params)
        profissionais = c.fetchall()
        conn.close()

        return jsonify({"status": "ok", "dados": [dict(p) for p in profissionais]})

    except Exception as e:
        return jsonify({"status": "erro", "msg": str(e)}), 500

# ═══════════════════════════════════════════
# AGENDAMENTOS — CRIAR
# ═══════════════════════════════════════════
@app.route("/api/agendar", methods=["POST"])
@login_required
def agendar():
    dados           = request.json
    profissional_id = dados.get("profissional_id")
    servico         = dados.get("servico", "").strip()
    data            = dados.get("data")
    horario         = dados.get("horario")
    valor           = dados.get("valor", 0)

    if not all([profissional_id, servico, data, horario]):
        return jsonify({"status": "erro", "msg": "Preencha todos os campos"}), 400

    # Validar data
    try:
        data_obj = datetime.strptime(data, "%Y-%m-%d").date()
        if data_obj < datetime.today().date():
            return jsonify({"status": "erro", "msg": "Data não pode ser no passado"}), 400
    except ValueError:
        return jsonify({"status": "erro", "msg": "Data inválida"}), 400

    try:
        conn = get_db()
        c = conn.cursor()

        # Verificar conflito de horário
        c.execute("""
            SELECT id FROM agendamentos
            WHERE profissional_id = %s AND data = %s AND horario = %s
            AND status NOT IN ('cancelado')
        """, (profissional_id, data, horario))

        if c.fetchone():
            conn.close()
            return jsonify({"status": "erro", "msg": "Horário já ocupado"}), 409

        # Criar agendamento
        c.execute("""
            INSERT INTO agendamentos (cliente_id, profissional_id, servico, data, horario, valor, status)
            VALUES (%s, %s, %s, %s, %s, %s, 'aguardando_pagamento')
            RETURNING id
        """, (session["usuario_id"], profissional_id, servico, data, horario, valor))

        agendamento_id = c.fetchone()["id"]
        conn.commit()
        conn.close()

        return jsonify({
            "status": "ok",
            "msg":    "Agendamento criado!",
            "agendamento_id": agendamento_id
        })

    except Exception as e:
        return jsonify({"status": "erro", "msg": str(e)}), 500

# ═══════════════════════════════════════════
# AGENDAMENTOS — MEUS AGENDAMENTOS
# ═══════════════════════════════════════════
@app.route("/api/meus-agendamentos")
@login_required
def meus_agendamentos():
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("""
            SELECT a.*, p.nome as prof_nome, p.categoria
            FROM agendamentos a
            LEFT JOIN profissionais p ON a.profissional_id = p.id
            WHERE a.cliente_id = %s
            ORDER BY a.data DESC, a.horario DESC
        """, (session["usuario_id"],))
        agendamentos = c.fetchall()
        conn.close()
        return jsonify({"status": "ok", "dados": [dict(a) for a in agendamentos]})
    except Exception as e:
        return jsonify({"status": "erro", "msg": str(e)}), 500

# ═══════════════════════════════════════════
# AGENDAMENTOS — CANCELAR
# ═══════════════════════════════════════════
@app.route("/api/agendamento/<int:id>/cancelar", methods=["POST"])
@login_required
def cancelar_agendamento(id):
    try:
        conn = get_db()
        c = conn.cursor()

        # Verificar se o agendamento pertence ao usuário
        c.execute("SELECT * FROM agendamentos WHERE id = %s AND cliente_id = %s", (id, session["usuario_id"]))
        agendamento = c.fetchone()

        if not agendamento:
            conn.close()
            return jsonify({"status": "erro", "msg": "Agendamento não encontrado"}), 404

        c.execute("UPDATE agendamentos SET status = 'cancelado' WHERE id = %s", (id,))
        conn.commit()
        conn.close()

        return jsonify({"status": "ok", "msg": "Agendamento cancelado"})
    except Exception as e:
        return jsonify({"status": "erro", "msg": str(e)}), 500

# ═══════════════════════════════════════════
# AVALIAÇÕES — CRIAR
# ═══════════════════════════════════════════
@app.route("/api/avaliar", methods=["POST"])
@login_required
def avaliar():
    dados           = request.json
    profissional_id = dados.get("profissional_id")
    agendamento_id  = dados.get("agendamento_id")
    nota            = dados.get("nota")
    comentario      = dados.get("comentario", "").strip()

    if not all([profissional_id, nota]):
        return jsonify({"status": "erro", "msg": "Nota obrigatória"}), 400

    if not isinstance(nota, int) or nota < 1 or nota > 5:
        return jsonify({"status": "erro", "msg": "Nota deve ser entre 1 e 5"}), 400

    try:
        conn = get_db()
        c = conn.cursor()

        c.execute("""
            INSERT INTO avaliacoes (cliente_id, profissional_id, agendamento_id, nota, comentario)
            VALUES (%s, %s, %s, %s, %s)
        """, (session["usuario_id"], profissional_id, agendamento_id, nota, comentario))

        # Atualizar média do profissional
        c.execute("""
            UPDATE profissionais SET avaliacao = (
                SELECT ROUND(AVG(nota)::numeric, 1) FROM avaliacoes WHERE profissional_id = %s
            ) WHERE id = %s
        """, (profissional_id, profissional_id))

        conn.commit()
        conn.close()

        return jsonify({"status": "ok", "msg": "Avaliação enviada!"})
    except Exception as e:
        return jsonify({"status": "erro", "msg": str(e)}), 500

# ═══════════════════════════════════════════
# ADMIN — DASHBOARD
# ═══════════════════════════════════════════
@app.route("/api/admin/dashboard")
@login_required
@admin_required
def admin_dashboard():
    try:
        conn = get_db()
        c = conn.cursor()

        c.execute("SELECT COUNT(*) as total FROM usuarios WHERE perfil = 'cliente'")
        total_clientes = c.fetchone()["total"]

        c.execute("SELECT COUNT(*) as total FROM profissionais WHERE ativo = TRUE")
        total_profissionais = c.fetchone()["total"]

        c.execute("SELECT COUNT(*) as total FROM agendamentos WHERE DATE_TRUNC('month', criado_em) = DATE_TRUNC('month', NOW())")
        total_agendamentos = c.fetchone()["total"]

        c.execute("SELECT COALESCE(SUM(taxa_zuli), 0) as total FROM pagamentos WHERE status = 'pago' AND DATE_TRUNC('month', criado_em) = DATE_TRUNC('month', NOW())")
        receita_mes = c.fetchone()["total"]

        conn.close()

        return jsonify({
            "status": "ok",
            "dados": {
                "total_clientes":     total_clientes,
                "total_profissionais": total_profissionais,
                "total_agendamentos": total_agendamentos,
                "receita_mes":        float(receita_mes)
            }
        })
    except Exception as e:
        return jsonify({"status": "erro", "msg": str(e)}), 500

# ═══════════════════════════════════════════
# ADMIN — APROVAR PROFISSIONAL
# ═══════════════════════════════════════════
@app.route("/api/admin/profissional/<int:id>/aprovar", methods=["POST"])
@login_required
@admin_required
def aprovar_profissional(id):
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("UPDATE profissionais SET aprovado = TRUE WHERE id = %s", (id,))
        conn.commit()
        conn.close()
        return jsonify({"status": "ok", "msg": "Profissional aprovado!"})
    except Exception as e:
        return jsonify({"status": "erro", "msg": str(e)}), 500

# ═══════════════════════════════════════════
# INICIAR APP
# ═══════════════════════════════════════════
if __name__ == "__main__":
    criar_tabelas()
    app.run(debug=False)
