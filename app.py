 # SDSC 2019 REHS - Open Science Chain
 # August 2019
 # Blockchain-Based Gradebook System
 # Author: Harris Beg | https://github.com/harrisbegca


from hashlib import sha256
import time, json, gnupg
from typing import List
from flask import Flask, render_template, request, redirect, jsonify
from forms import GradeForm
import nacl.signing, nacl.encoding

app = Flask(__name__)
registered_users = []

class CertificateIssuer:

    def __init__(self):
        self.transaction = []
        self.VERIFIER_KEY = nacl.signing.SigningKey.generate()
        self.signature = None
        self.VERIFY_KEY_HEX = None

    def set_transactions(self, transaction):
        self.transaction = transaction
        self.signature = self.VERIFIER_KEY.sign(str.encode(str(transaction)))
        self.VERIFY_KEY_HEX = self.VERIFIER_KEY.verify_key.encode(encoder=nacl.encoding.Base64Encoder)

    def public_key(self):
        return self.VERIFY_KEY_HEX

    def get_signed_data(self):
        return self.signature

    def __str__(self):
        print(self.signature)
        return str(self.signature)


certificate = CertificateIssuer()


# 1 Node Blockchain w/o PoW/PoS
username = ""


class Block:
    hash: str

    def __init__(self, index, transactions, timestamp, previous_block, certificate):
        self.index = index
        self.transactions = transactions
        self.timestamp = timestamp
        self.certificate = str(certificate)
        self.previous_hash = self.get_hash(previous_block)

    # Generates hash for previous block
    def get_hash(self, block):
        if block is not None:
            return sha256(json.dumps(block.__dict__).encode()).hexdigest()
        return "0"

    def check_authenticity(self):
        return self.get_hash() == sha256(json.dumps(self.__dict__).encode()).hexdigest()


class Blockchain:

    chain: List[Block]

    def __init__(self):
        self.pending_transactions = []
        self.chain = []

    def add_block(self, transactions, timestamp):
        global certificate
        if len(self.chain) == 0:
            self.create_genesis_block(transactions)
        else:
            certificate.set_transactions(transactions)
            verify_key = nacl.signing.VerifyKey(certificate.public_key(),
                                    encoder=nacl.encoding.Base64Encoder)  # Public key
            try:
                verify_key.verify(certificate.signature)
                print("VERIFIED")
                block = Block(len(self.chain), transactions, timestamp, previous_block=self.previous_block, certificate=certificate)
            except Exception:
                print("UNVERIFIED")
                return
            self.chain.append(block)

    def create_genesis_block(self, transactions):
        global certificate
        certificate.set_transactions(transactions)
        genesis = Block(0, transactions, time.time(), None, certificate=certificate)
        self.chain.append(genesis)  # No need to verify since it's the genesis block

    @property
    def previous_block(self):
        return self.chain[-1]

    def get_hash(self, i):
        # Retrieves top level index
        return self.chain[i + 1].previous_hash

    def __str__(self):
        result = ""
        for block in self.chain:
            result += str(block.__dict__)
        return result

    @property
    def chain_dict(self):
        s = ""
        duplicate = self.chain
        for block in duplicate:
            s += str(block.__dict__)
        return s

    @property
    def grades(self):
        s = []
        for block in self.chain:
            s.append({
                "transactions": block.transactions,
                "certificate": block.certificate
            })
        s.reverse()
        return s


block_chain = Blockchain()


@app.route('/')
def home():
    return render_template("home.html", home=True)

@app.route('/add_user')
def add_user():
    if request.args.get("id"):
        registered_users.append(request.args.get("id"))
        return jsonify(
            status_code=200
        )
    else:
        return jsonify(
            status_code=403
        )

@app.route('/create', methods=['GET', 'POST'])
def index():
    global username
    form = GradeForm()
    if request.method == 'POST':
        if username in registered_users and request.form["receiver"] in registered_users:
            block_chain.add_block(
                    transactions=[{
                        "teacher": username,
                        "grade": request.form["grade"],
                        "assignment": request.form["assignment"],
                        "receiver": request.form["receiver"],
                        "category": request.form["category"]
                    }],
                timestamp=time.time()
            )
            return redirect("/grades")
        else:
            return render_template("index.html", form=form, create=True, error="Teacher or student ID not found")
    user = request.args.get('user')
    if not user:
        return redirect("/")
    username = user
    return render_template("index.html", form=form, create=True)


@app.route('/grades')
def get_grades():
    global username
    if username != None:
        return render_template("grades.html", grades=block_chain.grades, username=username, grades_page=True)
    else:
        return redirect("/")


@app.route('/signout')
def sign_out():
    global username
    username = None
    return redirect('/')


@app.route('/chain')
def return_chain():
    return render_template("chain.html", blockchain=block_chain.chain_dict)


if __name__ == "__main__":
    app.run(port=5000, debug=True)
