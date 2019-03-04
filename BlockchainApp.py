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


class Wallet:
    walletID=None
    timestamp = datetime.datetime.now()
    publicKey=None
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
        print(transaction.toString())
        sendingWallet = None
        for wallet in self.wallets:
            if wallet.walletID==transaction.fromWalletID:
                sendingWallet=wallet
                break
        if(sendingWallet==None):
            print("Verification Failture: 1")
            return False
        if(Decimal(sendingWallet.balance)-Decimal(transaction.amount)<0):
            print("Verification Failture: 2")
            return False
        if(Decimal(transaction.amount<=0)):
            print("Verification Failture: 3")
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
        print(privateKey)       
        newWallet=Wallet()
        newWallet.timestamp=datetime.datetime.now()
        h=hashlib.sha256(
        str(newWallet.timestamp).encode('utf-8')
        ).hexdigest()
        newWallet.walletID=h
        newWallet.publicKey=publicKey
        self.wallets.append(newWallet)
        objectString = pickle.dumps(newWallet)
        for connection in self.connections:
            connection.send(b'\x12'+ objectString)
        return newWallet
    
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

    def printConnections(self):
        print(self.connections)
 
print()
print("Welcome the Blockchain Application!")
print("***************************")
blockchainNode=BlockchainNode()
while True:
    print("*******************")
    print("        Menu       ")
    print("*******************")
    print("ID   Selection")
    print("1    Connect to network")
    print("2    Create wallet")
    print("3    Display wallets")
    print("4    Set mining wallet")
    print("5    Post message to chain")
    print("6    Display connections")
    print("7    Exit")
    print("*******************")
    selection = input("Select a menu option id: ")
    while(selection !="1" and selection !="2" and selection !="3" and selection!="4" and selection !="5"and selection !="7" and selection !="6"):
        print("*******************")
        print("        Menu       ")
        print("*******************")
        print("ID   Selection")
        print("1    Connect to network")
        print("2    Create wallet")
        print("3    Display wallets")
        print("4    Set mining wallet")
        print("5    Post message to chain")
        print("6    Display connections")
        print("7    Exit")
        print("*******************")
        selection = input("Select a menu option id: ")
    if(selection=="1"):
        addr = input("Enter IP address to connect to: ")
        connect=True
        for peer in blockchainNode.peers:
            if(peer == addr):
                connect=False
        if(connect):
            blockchainNode.createManualConnection(addr)
        else:
            print("Already connected")
    elif(selection=="2"):
        newWallet=blockchainNode.createWallet()
        print("WalletID: "+newWallet.walletID)
    elif(selection=="3"):
        for wallet in blockchainNode.wallets:
            print(wallet.walletID+ " ", wallet.balance)
    elif(selection=="4"):
        addr = input("Enter mining wallet ID: ")
        blockchainNode.setMiningWallet(addr)
    elif(selection=="5"):
        mes=input("Enter message: ")
        blockchainNode.sendMessage(mes)
    elif(selection=="6"):
        blockchainNode.printConnections()
    else:
        sys.exit()
