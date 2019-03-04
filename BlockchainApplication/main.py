#For blockchain
import datetime
import hashlib
#For blockchain node
import socket
import threading
import sys
import time
from random import randint
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
import pickle
from decimal import Decimal
import mysql.connector

mydb = mysql.connector.connect(
  host="localhost",
  user="root",
  passwd="blockchain",
  database="blockchainapp"
)

mycursor = mydb.cursor()


class Wallet:
    walletID=None
    timestamp = datetime.datetime.now()
    publicKey=None
    balance=0

class LocalWallet:
    walletID=None
    timestamp = datetime.datetime.now()
    publicKey=None
    privateKey=None
    balance=0


class Transaction:
    timestamp = datetime.datetime.now()
    fromWalletID = None
    toWalletID = None
    amount=0
    signature = None

    def toString(self):
        return "\n\tFrom: "+str(self.fromWalletID)+"\n\tTo: "+str(self.toWalletID)+"\n\tAmount: "+str(self.amount)

class Block:
    index = 0
    transaction = None
    data=None
    hash = None
    nonce = 0
    previousHash = 0x0
    timestamp = datetime.datetime.now()
    minerWallet=None
    def toString(self):
        if(self.data==None and not self.transaction==None):
            return "*************\nHash: " + str(self.hash) +"\nTimestamp: "+str(self.timestamp)+ "\nIndex: " + str(self.index)+ "\nTransaction: " + self.transaction.toString() + "\nNonce: " + str(self.nonce)+"\nPrev-Hash: "+str(self.previousHash)+"\nMining Wallet: "+str(self.minerWallet)+"\n*************"
        if(self.transaction==None and not self.data==None):
                    return "*************\nHash: " + str(self.hash) +"\nTimestamp: "+str(self.timestamp)+ "\nIndex: " + str(self.index) + "\nData "+ str(self.data) + "\nNonce: " + str(self.nonce)+"\nPrev-Hash: "+str(self.previousHash)+"\nMining Wallet: "+str(self.minerWallet)+"\n*************"
        if(self.transaction==None and self.data==None):
                    return "*************\nHash: " + str(self.hash) +"\nTimestamp: "+str(self.timestamp)+ "\nIndex: " + str(self.index) + "\nNonce: " + str(self.nonce)+"\nPrev-Hash: "+str(self.previousHash)+"\nMining Wallet: "+str(self.minerWallet)+"\n*************"
        else:
            return "*************\nHash: " + str(self.hash) +"\nTimestamp: "+str(self.timestamp)+ "\nIndex: " + str(self.index) + "n\Data "+ str(self.data) + "\nTransaction: " + self.transaction.toString() + "\nNonce: " + str(self.nonce)+"\nPrev-Hash: "+str(self.previousHash)+"\nMining Wallet: "+str(self.minerWallet)+"\n*************"


class Blockchain:
    ##Create constants
    difficulty = 4
    maxNonce = 2**32
    target = 2 ** (256-difficulty)
    ##Create genesis block
    blocks=[]
    gBlock=Block()
    gBlock.data="Genesis"
    gBlock.timestamp=datetime.datetime.now()
    gBlock.index=0
    gBlock.nonce=0
    for x in range(0,maxNonce):
            hashToCheck=hashlib.sha256(
                str(gBlock.nonce).encode('utf-8') +
                str(gBlock.transaction).encode('utf-8') +
                str(gBlock.previousHash).encode('utf-8') +
                str(gBlock.timestamp).encode('utf-8') +
                str(gBlock.index).encode('utf-8')
                ).hexdigest()
            gBlock.nonce = int(gBlock.nonce) + 1
            prefix=""
            for i in range(0,difficulty):
                prefix+="0"
            if(hashToCheck.startswith(prefix)):
                gBlock.hash=hashToCheck
                break
    blocks.append(gBlock)
    def add(self, block):
        self.blocks.append(block)

    def createBlock(self, oldBlock, data, transaction,miningWalletID):
        print("Mining block:")
        newBlock = Block()
        newBlock.timestamp=datetime.datetime.now()
        newBlock.index = oldBlock.index+1
        newBlock.previousHash= oldBlock.hash
        newBlock.data=data
        newBlock.transaction=transaction
        newBlock.nonce=0
        newBlock.minerWallet=miningWalletID
        for x in range(0,self.maxNonce):
            hashToCheck=hashlib.sha256(
                str(newBlock.nonce).encode('utf-8') +
                str(newBlock.transaction).encode('utf-8') +
                str(newBlock.previousHash).encode('utf-8') +
                str(newBlock.timestamp).encode('utf-8') +
                str(newBlock.index).encode('utf-8')
                ).hexdigest()
            newBlock.nonce = int(newBlock.nonce) + 1
            sys.stdout.write("\r" + hashToCheck)
            sys.stdout.flush()
            prefix=""
            for i in range(0,self.difficulty):
                prefix+="0"
            if(hashToCheck.startswith(prefix)):
                print()
                print("Block found!")
                newBlock.hash=hashToCheck
                print(newBlock.toString())
                break
        return newBlock

    def getSize(self):
        return len(self.blocks)

class BlockchainNode:

    blockchain=Blockchain()
    wallets=[]
    blockchainToCompare=[]
    miningWalletID=None

    MINING_REWARD=10.0

    ##Get wallets from db
    mycursor.execute("SELECT * FROM wallets")
    wals=mycursor.fetchall()
    for wallet in wals:
        tempW=Wallet()
        tempW.walletID=wallet[0]
        tempW.timestamp=wallet[1]
        tempW.publicKey=wallet[2]
        tempW.balance=wallet[3]
        wallets.append(tempW)

    serverSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connections = []
    peers = [] #addresses of known nodes

    socketsTo=[]
    clientThreads=[]

    def handleBlockBalances(self,block):
        if(not block.transaction=="Genesis"):
            toWallet=None
            fromWallet=None
            miningWallet=None
            for wallet in self.wallets:
                if(not block.transaction==None):
                    if(wallet.walletID==block.transaction.fromWalletID):
                        fromWallet=wallet
                    if(wallet.walletID==block.transaction.toWalletID):
                        toWallet=wallet
                if(wallet.walletID==block.minerWallet):
                    miningWallet=wallet
            if(not block.transaction==None):
                if(not toWallet==None):
                    toWallet.balance=Decimal(toWallet.balance)+Decimal(block.transaction.amount)
                if(not fromWallet==None):
                    fromWallet.balance=Decimal(fromWallet.balance)-Decimal(block.transaction.amount)
            if(not miningWallet==None):
                miningWallet.balance=Decimal(miningWallet.balance)+Decimal(self.MINING_REWARD)

    def verifyTransaction(self,transaction):
        print("Verifying new transaction")
        sendingWallet = None
        for wallet in self.wallets:
            if wallet.walletID==transaction.fromWalletID:
                sendingWallet=wallet
                break
        if(sendingWallet==None):
            return False
        if(Decimal(sendingWallet.balance)-Decimal(transaction.amount)<0):
            return False
        if(Decimal(transaction.amount<=0)):
            return False
        hash=SHA256.new(
            str(transaction.timestamp).encode('utf-8') +
            str(transaction.toWalletID).encode('utf-8') +
            str(transaction.fromWalletID).encode('utf-8') +
            str(transaction.amount).encode('utf-8')).digest()
        publicKey=RSA.importKey(sendingWallet.publicKey)
        return publicKey.verify(hash,transaction.signature)

    def updatePeers(self,peerData):
        newPeers=str(peerData,"utf-8").split(",")[:-1]
        for np in newPeers:
            connect=True
            for peer in self.peers:
                if(np==peer):
                    connect=False
            if(connect):
                clientThread=threading.Thread(target=self.client, args=(np,))
                clientThread.daemon=True
                clientThread.start()
                self.clientThreads.append(clientThread)
                self.peers.append(np)

    def addWallet(self,walletData):
        newWallet=pickle.loads(walletData)
        alreadyExists=False
        for wallet in self.wallets:
            if(wallet.walletID==newWallet.walletID):
                alreadyExists=True
        if(not alreadyExists):
            mycursor.execute("INSERT INTO wallets(walletID,publicKey, timestamp,balance) VALUES(%s,%s,%s,%s)",(newWallet.walletID,newWallet.publicKey,newWallet.timestamp,newWallet.balance))
            mydb.commit()
            self.wallets.append(newWallet)
            print("New wallet received")

    def updateWallets(self, walletData):
        newWallets=pickle.loads(walletData)
        for newWallet in newWallets:
            alreadyExists=False
            for oldWallet in self.wallets:
                if(oldWallet.walletID==newWallet.walletID):
                    alreadyExists=True
            if(not alreadyExists):
                self.wallets.append(newWallet)
        print("Wallets updated")


    def addBlock(self,blockData):
        newBlock=pickle.loads(blockData)
        if(len(self.blockchain.blocks)==newBlock.index and newBlock.previousHash==self.blockchain.blocks[len(self.blockchain.blocks)-1].hash):
            # if(newBlock.transaction==None):
            #     mycursor.execute("INSERT INTO blocks(hash,index,timestamp,nonce,,minerWalletpreviousHash,data) VALUES(%s,%s,%s,%s,%s,%s,%s)",(newBlock.hash,newBlock.index,newBlock.timestamp,newBlock.nonce,newBlock.minerWallet,newBlock.previousHash,newBlock.data))
            # else:
            #     mycursor.execute("INSERT INTO blocks(hash,index, timestamp,previousHash,nonce, minerWallet,data,transactionTimestamp, fromWalletID,"
            #                  " toWalletID, amount, signature) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",(newBlock.hash,newBlock.index,newBlock.timestamp,
            #                                                                                                 newBlock.previousHash,newBlock.nonce,newBlock.minerWallet,newBlock.data,
            #                                                                                                 newBlock.transaction.timestamp,newBlock.transaction.fromWalletID,
            #                                                                                                 newBlock.transaction.toWalletID,newBlock.transaction.amount,
            #                                                                                                 newBlock.transaction.signature))
            mydb.commit()
            self.handleBlockBalances(newBlock)
            self.blockchain.blocks.append(newBlock)
            print("New block received")
            print(newBlock.toString())
            objectString = pickle.dumps(newBlock)
            for connection in self.connections:
                connection.send(b'\x13'+ objectString)

    def addCompBlock(self,blockData):
        newBlock=pickle.loads(blockData)
        self.blockchainToCompare.append(newBlock)

    def compareBlockchain(self):
        print("Download complete")
        if(len(self.blockchainToCompare) > len(self.blockchain.blocks)):
            for wallet in self.wallets:
                wallet.balance=0
            self.blockchain.blocks.clear()
            for newBlock in self.blockchainToCompare:
                self.handleBlockBalances(newBlock)
                self.blockchain.blocks.append(newBlock)
            print("Blockchain updated")
        if(len(self.blockchain.blocks)==1 and self.blockchainToCompare[0].timestamp < self.blockchain.blocks[0].timestamp):
            for wallet in self.wallets:
                wallet.balance=0
            self.blockchain.blocks.clear()
            for newBlock in self.blockchainToCompare:
                self.handleBlockBalances(newBlock)
                self.blockchain.blocks.append(newBlock)
            print("Blockchain updated")
        self.blockchainToCompare.clear()

    def sendMsg(self,sock):
        while True:
            sock.send(bytes(input(""), 'utf-8'))

    def sendMessage(self, message):
        for connection in self.connections:
            connection.send(bytes(message,'utf-8'))

    def manageTransaction(self, tData):
        newT=pickle.loads(tData)
        print(newT.fromWalletID)
        if(self.verifyTransaction(newT)):
            print("Transaction verified")
            newBlock=self.blockchain.createBlock(self.blockchain.blocks[len(self.blockchain.blocks)-1],None,newT,self.miningWalletID)
            objectString = pickle.dumps(newBlock)
            for connection in self.connections:
                connection.send(b'\x13'+ objectString)
        else:
            print("Verification failed")

    def __init__(self):
        serverThread=threading.Thread(target=self.server)
        serverThread.daemon=True
        serverThread.start()

    def server(self):
        self.serverSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.serverSock.bind(('0.0.0.0', 10000))
        self.serverSock.listen(1)
        print("Internal server running")
        while True:
            #c=connection, a=address
            c,a = self.serverSock.accept()
            #Create new thread to listen to new connection
            connectionThread=threading.Thread(target=self.cListener,args=(c,a))
            connectionThread.daemon=True
            connectionThread.start()
            self.connections.append(c)
            attemptConnection = True
            print(str(a[0])+':'+ str(a[1]), "connected")
            for peer in self.peers:
                if peer == a[0]:
                    attemptConnection = False
            if(attemptConnection):
                #Create new thread to be client of new connection if not already connected
                clientThread=threading.Thread(target=self.client, args=(a[0],))
                clientThread.daemon=True
                clientThread.start()
                self.clientThreads.append(clientThread)
            addPeer=True
            for peer in self.peers:
                if(peer==a[0]):
                    addPeer=False
            if(addPeer):
                self.peers.append(a[0])
            #self.sendPeers()

    def client(self,address):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.connect((address,10000))
        while True:
            data=sock.recv(4096)
            if not data:
                break
            if(data[0:1] == b'\x11'):
                self.updatePeers(data[1:])
            elif(data[0:1] == b'\x12'):
                self.addWallet(data[1:])
            elif(data[0:1] == b'\x13'):
                self.addBlock(data[1:])
            elif(data[0:1] == b'\x14'):
                print("Downloading blockchain...")
                self.blockchainToCompare.clear()
            elif(data[0:1] == b'\x15'):
                self.addCompBlock(data[1:])
            elif(data[0:1] == b'\x16'):
                self.compareBlockchain()
            elif(data[0:1] == b'\x17'):
                self.updateWallets(data[1:])
            elif(data[0:1] == b'\x18'):
                self.manageTransaction(data[1:])
            else:
                newBlock=self.blockchain.createBlock(self.blockchain.blocks[len(self.blockchain.blocks)-1],str(data,'utf-8'),None,self.miningWalletID)
                objectString = pickle.dumps(newBlock)
                for connection in self.connections:
                    connection.send(b'\x13'+ objectString)

    def cListener(self,c,a):
        #Send blockchain to new connection
        c.send(b'\x14')
        for block in self.blockchain.blocks:
            objectString = pickle.dumps(block)
            c.send(b'\x15'+ objectString)
            time.sleep(0.05)
        time.sleep(0.05)
        c.send(b'\x16')
        time.sleep(0.05)
        ##Send wallets
        for wallet in self.wallets:
            walletString=pickle.dumps(wallet)
            c.send(b'\x12'+ walletString)
            time.sleep(0.05)
        #Send list of all current connections to new connection
        p =""
        for peer in self.peers:
            if(not peer == a[0]):
                p=p+peer+","
        c.send(b'\x11'+ bytes(p,"utf-8"))
        while True:
            data=c.recv(4096)
            if not data:
                print(str(a[0])+':'+ str(a[1]), "disconnected")
                self.connections.remove(c)
                self.peers.remove(a[0])
                c.close()
                #self.sendPeers()
                break

    def sendPeers(self):
        p =""
        for peer in self.peers:
            p=p+peer+","
        for connection in self.connections:
            connection.send(b'\x11'+ bytes(p,"utf-8"))

    def createManualConnection(self,address):
        connect=True
        for peer in self.peers:
            if(peer==address):
                connect=False
                return False
        if(connect):
            try:
                clientThread=threading.Thread(target=self.client, args=(address,))
                clientThread.daemon=True
                clientThread.start()
                self.clientThreads.append(clientThread)
                self.peers.append(address)
                return True
            except:
                return False

    def createWallet(self):
        key = RSA.generate(1024)
        publicKey=key.publickey().exportKey().decode('utf-8')
        privateKey=key.exportKey().decode('utf-8')
        newWallet=Wallet()
        returnWallet=LocalWallet()
        returnWallet.timestamp=datetime.datetime.now()
        newWallet.timestamp=datetime.datetime.now()
        h=hashlib.sha256(
        str(newWallet.timestamp).encode('utf-8')
        ).hexdigest()
        returnWallet.walletID=h
        newWallet.walletID=h
        newWallet.publicKey=publicKey
        returnWallet.publicKey=publicKey
        returnWallet.privateKey=privateKey
        self.wallets.append(newWallet)
        objectString = pickle.dumps(newWallet)
        mycursor.execute("INSERT INTO wallets(walletID,publicKey, timestamp,balance) VALUES(%s,%s,%s,%s)",(newWallet.walletID,newWallet.publicKey,newWallet.timestamp,newWallet.balance))
        mydb.commit()
        for connection in self.connections:
            connection.send(b'\x12'+ objectString)
        return returnWallet

    def createTransaction(self,fromWID,privKey,amt,toWID):
        toW=None
        fromW=None
        for wallet in self.wallets:
            if(wallet.walletID==fromWID):
                fromW=wallet
            if(wallet.walletID==toWID):
                toW=wallet
        if(not toW==None and not fromW==None):
            newTransaction= Transaction()
            newTransaction.timestamp=datetime.datetime.now()
            newTransaction.toWalletID=toW.walletID
            newTransaction.fromWalletID=fromW.walletID
            newTransaction.amount=amt
            hash=SHA256.new(
                str(newTransaction.timestamp).encode('utf-8') +
                str(newTransaction.toWalletID).encode('utf-8') +
                str(newTransaction.fromWalletID).encode('utf-8') +
                str(newTransaction.amount).encode('utf-8')).digest()
            privateKey=RSA.importKey(privKey)
            signature= privateKey.sign(hash,'')
            newTransaction.signature=signature
            objectString=pickle.dumps(newTransaction)
            ##print(self.connections)
            for connection in self.connections:
                connection.send(b'\x18'+ objectString)
            return newTransaction

    def walletExists(self, id):
        for wallet in self.wallets:
            if(wallet.walletID==id):
                return True
        return False

    def setMiningWallet(self,walletID):
        self.miningWalletID=walletID

###################################### WEBSITE METHODS #######################################
#For website
from flask import Flask, request, render_template,redirect
from wtforms import Form, StringField, TextAreaField, PasswordField, SelectField, validators,DecimalField
import csv
from flask_mysqldb import MySQL
from Crypto.Cipher import AES
class Session:
    connectedToNetwork=False
    LoggedIn=False
    myWallets=[]
    username=None
    firstName=None
    lastName=None
    password=None
    miningWalletSet=False
    miningWallet=None
    newWallet=None

session=Session()

app = Flask(__name__)

app.config['MYSQL_HOST'] ='localhost'
app.config['MYSQL_USER'] ='<your_username>'
app.config['MYSQL_PASSWORD'] ='<your_password>'
app.config['MYSQL_DB'] ='blockchainapp'
app.config['MYSQL_CURSORCLASS'] ='DictCursor'

mysql=MySQL(app)
blockchainNode=BlockchainNode()
class ConnectionForm(Form):
    addr=StringField('Connection Address', [validators.DataRequired()])

class MiningWalletForm(Form):
    id=StringField('Mining Wallet ID', [validators.DataRequired()])

@app.route('/',methods=['GET','POST'])
def index():
    if(session.LoggedIn==False):
        return redirect("/login")
    recentTList=[]
    for block in reversed(blockchainNode.blockchain.blocks):
        if(len(recentTList)<4):
            if(not block.transaction==None):
                recentTList.append(block.transaction)
        else:
            break
    for nodeWallet in blockchainNode.wallets:
        for localWallet in session.myWallets:
            if(nodeWallet.walletID==localWallet.walletID):
                localWallet.balance=nodeWallet.balance
    connectionForm=ConnectionForm(request.form)
    miningWalletForm=MiningWalletForm(request.form)
    if request.method=='POST' and connectionForm.validate():
        addr=connectionForm.addr.data
        blockchainNode.createManualConnection(addr)
        session.connectedToNetwork=True
        return render_template("index.html", connectionForm=connectionForm, session=session, miningWalletForm=miningWalletForm, peers=blockchainNode.peers,recentTransactions=recentTList,userWallets=session.myWallets)
    elif request.method=='POST' and miningWalletForm.validate():
        id=miningWalletForm.id.data
        blockchainNode.setMiningWallet(id)
        session.miningWallet=id
        session.miningWalletSet=True
        return render_template("index.html", connectionForm=connectionForm, session=session, miningWalletForm=miningWalletForm, peers=blockchainNode.peers, recentTransactions=recentTList,userWallets=session.myWallets)
    return render_template("index.html", connectionForm=connectionForm, session=session,miningWalletForm=miningWalletForm, peers=blockchainNode.peers, recentTransactions=recentTList,userWallets=session.myWallets)

class MessageForm(Form):
    mes=StringField('Message', [validators.DataRequired()])
@app.route('/message',methods=['GET','POST'])
def message():
    if(session.LoggedIn==False):
        return redirect("/login")
    messageForm=MessageForm(request.form)
    if request.method=='POST' and messageForm.validate():
        mes=messageForm.mes.data
        blockchainNode.sendMessage(mes)
        session.connectedToNetwork=True
        return redirect('/')
    return render_template("message.html", form=messageForm, session=session)

@app.route('/wallets')
def wallets():
    if(session.LoggedIn==False):
        return redirect("/login")
    return render_template("wallets.html", session=session,wallets=blockchainNode.wallets)

@app.route('/newWallet')
def newWallet():
    if(session.LoggedIn==False):
        return redirect("/login")
    session.newWallet=blockchainNode.createWallet()
    return render_template("newWallet.html", session=session, newWallet=session.newWallet)

@app.route('/saveWallet')
def saveWallet():
    if(session.newWallet==None):
        return redirect("/")
    session.myWallets.append(session.newWallet)
    cur=mysql.connection.cursor()
    cur.execute("INSERT INTO userWallets(walletID,publicKey, privateKey, timestamp,user) VALUES(%s,%s,%s,%s,%s)",(session.newWallet.walletID,session.newWallet.publicKey,session.newWallet.privateKey,session.newWallet.timestamp,session.username))
    mysql.connection.commit()
    cur.close()
    return redirect('/')

@app.route('/blocks')
def blocks():
    if(session.LoggedIn==False):
        return redirect("/login")
    return render_template("blocks.html", session=session,blocks=blockchainNode.blockchain.blocks)

@app.route('/about')
def about():
    if(session.LoggedIn==False):
        return redirect("/login")
    return render_template("about.html", session=session)

class RegisterForm(Form):
    firstName=StringField('First Name', [validators.Length(min=1,max=50)])
    lastName=StringField('Last Name', [validators.Length(min=1,max=50)])
    userName=StringField('Username', [validators.Length(min=4,max=25)])
    password=PasswordField('Password',
                           [validators.DataRequired(),
                            validators.EqualTo('confirm',
                                               message="Passwords don't match")])
    confirm=PasswordField('Confirm Password')

@app.route('/register',methods=['GET','POST'])
def register():
    form=RegisterForm(request.form)
    if request.method=='POST' and form.validate():
        firstName=form.firstName.data
        lastName=form.lastName.data
        username=form.userName.data
        password=form.password.data
        encryptedPass = hashlib.sha512(password.encode()).hexdigest()
        cur=mysql.connection.cursor()
        result=cur.execute("SELECT * FROM users WHERE userName = %s",[username])
        errors=[]
        if not result>0:
            cur.execute("INSERT INTO users(firstName,lastName, userName, passHash) VALUES(%s,%s,%s,%s)",(firstName,lastName,username,encryptedPass))
        else:
            errors.append("A user with that username already exists")
        mysql.connection.commit()
        cur.close()
        if(len(errors)==0):
            session.username=username
            session.firstName=firstName
            session.lastName=lastName
            session.LoggedIn=True
            return redirect('/')
        else:
            return render_template('register.html',form=form, errors=errors,session=session)
    return render_template('register.html',form=form,session=session)

class LoginForm(Form):
    userName=StringField('User Name', [validators.Length(min=1,max=50)])
    password=PasswordField('Password',[validators.DataRequired()])

@app.route('/login',methods=['GET','POST'])
def login():
    form=LoginForm(request.form)
    if request.method=='POST' and form.validate():
        username=form.userName.data
        password=form.password.data
        encryptedPass = hashlib.sha512(password.encode()).hexdigest()
        cur = mysql.connection.cursor()
        result=cur.execute("SELECT * FROM users WHERE userName = %s",[username])
        login=False
        firstName=None
        lastName=None
        if result>0:
            data=cur.fetchone()
            realPass=data['passHash']
            firstName=data['firstName']
            lastName=data['lastName']
            if(encryptedPass==realPass):
                login=True
        result=cur.execute("SELECT * FROM userWallets WHERE user = %s",[username])
        session.myWallets.clear()
        if result>0:
            wallets=cur.fetchall()
            for wallet in wallets:
                tempW=LocalWallet()
                tempW.walletID=wallet['walletID']
                tempW.privateKey=wallet['privateKey']
                tempW.publicKey=wallet['publicKey']
                session.myWallets.append(tempW)
        cur.close()
        errors=[]
        if(login==False):
            errors.append("Incorrect Login Information")
            return render_template('login.html',form=form,errors= errors,session=session)
        else:
            session.LoggedIn=True
            session.username=username
            session.firstName=firstName
            session.lastName=lastName
            session.password=password
            return redirect('/')
    return render_template('login.html',form=form,session=session)

class TransactionForm(Form):
    toWallet=StringField('Receiving Wallet ID', [validators.DataRequired()])
    privKey=TextAreaField('Sending Wallet Private Key', [validators.DataRequired()])
    fromWallet=StringField('Sending Wallet ID', [validators.DataRequired()])
    amount=DecimalField('Amount', [validators.DataRequired()])

@app.route('/transactions')
def transactions():
    if(session.LoggedIn==False):
        return redirect("/login")
    transList=[]
    for block in blockchainNode.blockchain.blocks:
        if(not block.transaction==None):
            transList.append(block.transaction)
    return render_template("transactions.html", session=session,transactions=transList)

@app.route('/transaction',methods=['GET','POST'])
def transaction():
    if(session.LoggedIn==False):
        return redirect("/login")
    form=TransactionForm(request.form)
    for nodeWallet in blockchainNode.wallets:
        for localWallet in session.myWallets:
            if(nodeWallet.walletID==localWallet.walletID):
                localWallet.balance=nodeWallet.balance
    if request.method=='POST' and form.validate():
        toW=form.toWallet.data
        fromW=form.fromWallet.data
        pk=form.privKey.data
        amt=form.amount.data
        privK=pk[:30]+ pk[30:-28].replace(' ', '\n') +pk[-28:]
        blockchainNode.createTransaction(fromW,privK,amt,toW)
        return redirect('/')
    return render_template('transaction.html',form=form,session=session,userWallets=session.myWallets)

@app.route('/logout')
def logout():
    session.LoggedIn=False
    session.firstName=None
    session.firstName=None
    session.username=None
    session.password=None
    session.miningWallet=None
    blockchainNode.setMiningWallet("")
    session.myWallets.clear()
    return redirect('/')

if __name__=="__main__":
    app.run(host="127.0.0.1")
