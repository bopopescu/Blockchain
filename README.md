# Blockchain Application

My name is Gordon MacMaster. I am a junior computer science and information science major at the University of Vermont. I have six years of programing experience and have completed a software development internship with Pennsylvania Multifamily Asset Managers and in spring/summer 2019 I will be working for Tesla in Fremont, California as a software development intern.

This application serves as a way of getting to know the uses of a distributed blockchain. Written in python, the blockchain implements a custom peer-to-peer networking, cryptographic security measures, and the ability to send and recieve transactions. This blockchain allows users to serve as a mining node or a full node capable of generating transactions.

## Installation

Use the package manager [pip](https://pip.pypa.io/en/stable/) to install foobar.

```bash

```
## Create Database

Install mqsql

```bash
pip install mysqlclient
CREATE DATABASE `blockchainapp` /*!40100 DEFAULT CHARACTER SET latin1 */;


CREATE TABLE `blocks` (
  `hash` varchar(200) NOT NULL,
  `index` int(11) NOT NULL,
  `timestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `nonce` int(11) NOT NULL,
  `minerWallet` varchar(200) DEFAULT NULL,
  `previousHash` varchar(200) DEFAULT NULL,
  `data` varchar(100) DEFAULT NULL,
  `transactionTimestamp` timestamp NULL DEFAULT NULL,
  `fromWalletID` varchar(200) DEFAULT NULL,
  `toWalletID` varchar(200) DEFAULT NULL,
  `amount` double DEFAULT NULL,
  `signature` varchar(1000) DEFAULT NULL,
  PRIMARY KEY (`hash`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;


CREATE TABLE `users` (
  `userId` int(11) NOT NULL AUTO_INCREMENT,
  `firstName` varchar(60) NOT NULL,
  `lastName` varchar(60) NOT NULL,
  `userName` varchar(60) NOT NULL,
  `passHash` varchar(200) NOT NULL,
  PRIMARY KEY (`userId`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=latin1;


CREATE TABLE `userWallets` (
  `walletID` varchar(200) NOT NULL,
  `publicKey` varchar(1000) NOT NULL,
  `privateKey` varchar(1000) NOT NULL,
  `timestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `balance` double DEFAULT NULL,
  `user` varchar(60) NOT NULL,
  PRIMARY KEY (`walletID`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;


CREATE TABLE `wallets` (
  `walletID` varchar(200) NOT NULL,
  `timestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `publicKey` varchar(1000) NOT NULL,
  `balance` double NOT NULL,
  PRIMARY KEY (`walletID`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

```
## Usage

Open /BlockchainApplication in IDE such as PyCharm
Change lines 517 & 518 to your mysql credentials 
Run program
Open browser
Go to: http://127.0.0.1:5000/
Create account/login
Add other running connections on local network by IP

If you want to just run a mining node:
```bash
cd <project folder>
python BlockchainApp.py
```
Follow menu options to add other connections via IP

## License
[MIT](https://choosealicense.com/licenses/mit/)
