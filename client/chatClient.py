import socket, select, string, sys, os, random, datetime, pyDH, pickle, threading, time, getpass
from datetime import datetime, date
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key

try:
	f = open('chatConf.conf', 'r')
	for line in f:
		if 'Server' in line :
			server, serverIp, serverPort = line.split(":",2)
			host = serverIp 
			port = int(serverPort)

except:
	print "Config File missing! Please make sure configuration file is in same folder!"
	os._exit(1)
challenge_response = '0'
timestamp = 0.0
global activeUserlist
activeUserlist =[] # server side list
global ticket_socket
global activeuserslist
global authclientlist
authclientlist = []
activeuserslist = []
global logoutnounce
global onetime_message 
onetime_message = 'nothing'
global dhClient_sharedkey

def encrypt(key, plaintext, additional_authenticated_data):
    iv = os.urandom(16)
    encryptor = Cipher(algorithms.AES(key),modes.GCM(iv),backend=default_backend()).encryptor() # AES_GCM mode with 256 bit symmetric key
    encryptor.authenticate_additional_data(additional_authenticated_data) # Authenticaed data in our case its hash(plain_message)
    # sign hash of message with private key
    m = plaintext
    ciphertext = encryptor.update(m) + encryptor.finalize()
    return (iv, ciphertext, encryptor.tag)

def asymmetric_encryption(key, message):
    ciphertext = key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None))
    return ciphertext

#function to decryptClientLoginMessage cookie
def asymmetric_decryption(key, message):

	decryptedMsg = key.decrypt(
			message,
			padding.OAEP(
				    mgf=padding.MGF1(algorithm=hashes.SHA1()),
				    algorithm=hashes.SHA1(),
				    label=None))
	return decryptedMsg

def sign_message(key, message):
    signer = key.signer(padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
    signer.update(message)
    signature = signer.finalize()
    return signature

def hashm(message):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(message)
    hash_of_message = digest.finalize()
    return hash_of_message

def generate_asymmetric_key():		
	client_private_key = rsa.generate_private_key(
		public_exponent=65537,
		key_size=2048,
		backend=default_backend()
		)
	client_public_key = client_private_key.public_key()
	return client_private_key, client_public_key 

def break_challenge(bits_118, hash_of_challenge):
	for i in xrange(0,1024):
		iterator = str(bin(i)[2:12]).rjust(10,'0')
		if(hashm(bits_118+iterator+'127.0.0.1') == hash_of_challenge):
			challenge_response = iterator
			break
	return challenge_response

def load_server_public_key():
	with open("server_public_key.der", "rb") as key_file:
	     	server_public_key = serialization.load_der_public_key(
		  		key_file.read(),
				backend=default_backend())
	return server_public_key

#function to verify signatures
def verifySignature(key,signature,message):
	verifier = key.verifier(
			signature,
			padding.PSS(
				mgf = padding.MGF1(hashes.SHA256()),
				salt_length = padding.PSS.MAX_LENGTH
			),
			hashes.SHA256()
		)
	try:
		verifier.update(message)
		verifier.verify()
		return True
	except:
		print "Error in verifying Signature!"
		return False

#function symmetric decryption 
def symmetric_decryptServermsg(key, associated_data, iv, ciphertext, tag):
    decryptor = Cipher(algorithms.AES(key),modes.GCM(iv, tag),backend=default_backend()).decryptor()
    decryptor.authenticate_additional_data(associated_data)
    return decryptor.update(ciphertext) + decryptor.finalize()

def get_timestamp() :
    	return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

#function to verify Timestamp 
def verifyTimestamp(client_timestamp):
	 
	server_timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
	c_ts = datetime.strptime(client_timestamp, '%Y-%m-%d %H:%M:%S')
	s_ts = datetime.strptime(server_timestamp, '%Y-%m-%d %H:%M:%S')
	elapsed = s_ts - c_ts
	hours, remainder = divmod(elapsed.seconds, 3600)
	minutes, seconds = divmod(remainder, 60)
	if(minutes > 2):
		return False
	
	return True

def get_ActiveUserList(username,client_Option,dnp) :

	plaintext = dnp+'***'+username+'***'+ get_timestamp()			
	additional_authenticated_data = b'list'
	iv,ciphertext,tag = encrypt(dhClient_sharedkey[0:32], plaintext, additional_authenticated_data)
	client_socket.send(iv +'***'+ ciphertext+'***'+tag+'***'+ additional_authenticated_data)
	

def peer_thread(ticket_socket, ticket_clientbytepublickey):
	while True:
		peer_data = ticket_socket.recv(4096)
		if(peer_data.startswith('peerticket2')):
			responsetype, peer_auth2, signed_peer_DH_public_key, peer_DH_public_key = peer_data.split("***",3)
			try:
				decrypted_peermsg = asymmetric_decryption(client_private_key, peer_auth2)
			except:
				print "Error in assymmetric decrypting message!!!"	
			client_username, ticket_username, ticket_timestamp, timestamp = decrypted_peermsg.split("***",3)
			### verify ticket_timestamp to be less than 10 mins here
			ticket_clientpublickey = load_pem_public_key(ticket_clientbytepublickey, backend=default_backend())
			if(verifySignature(ticket_clientpublickey,signed_peer_DH_public_key, peer_DH_public_key)):
			
				d2 = pyDH.DiffieHellman()
				peer2_DH_public_key = d2.gen_public_key()
				peer_sharedkey = d2.gen_shared_key(long(peer_DH_public_key))
				try:
					signed_peer2_DH_public_key = sign_message(client_private_key, str(peer2_DH_public_key))
				except:
					print "Error in signing message!!!"
				timestamp = get_timestamp()
				nounce = os.urandom(16)
				plaintext = timestamp +'***'+ nounce
				additional_authenticated_data = b'peerticket3'
				try:
					iv,ciphertext, tag = encrypt(peer_sharedkey[0:32], plaintext, additional_authenticated_data)
				except:
					print "Error in symmetric encryption!!!"
				ticket_socket.send('peerticket3'+'***'+iv+'***'+ciphertext+'***'+ tag +'***'+additional_authenticated_data+'***'+signed_peer2_DH_public_key+'***'+str(peer2_DH_public_key))
				
		
		if(peer_data.startswith('peerticket4')):
			responsetype, nounceresponse = peer_data.split("***",1)
			if (nounce==nounceresponse):
				print "Client Aunthenticated!"
				
				activeuserslist.append((ticket_username, peer_sharedkey[0:32],ticket_socket))
				authclientlist.append(ticket_username)
				additional_authenticated_data = b'message'
				plaintext = onetime_message + '***' + get_timestamp() + '***' + client_username
				try:
					iv, ciphertext, tag = encrypt(peer_sharedkey[0:32], plaintext, additional_authenticated_data)
				except:
					print "Error in symmetric encryption!!!"
				try:
					signature_hash = sign_message( client_private_key,hashm(onetime_message))
				except:
					print "Error in signing message!!!"	
				ticket_socket.send('message'+'***'+iv +'***'+ ciphertext+'***'+ tag+'***'+additional_authenticated_data +'***'+signature_hash+'***'+hashm(onetime_message))


		if(peer_data.startswith('message')):
			responsetype, iv, ciphertext, tag, associated_data, signature, hashofmessage = peer_data.split("***",6)
			decryptedmessage = symmetric_decryptServermsg(peer_sharedkey[0:32], associated_data, iv, ciphertext, tag)
			message, timestamp, username2 = decryptedmessage.split('***', 2)	
				
			if(verifySignature(ticket_clientpublickey,signature, hashm(message)) and verifyTimestamp(timestamp)):
				# verify timestamp and then print
				if (message == 'logout'):
					for authuserobject in activeuserslist:
						if username2 in authuserobject:
							activeuserslist.remove(authuserobject)
							authclientlist.remove(username2)		
				else:
					print "<" + username2 + ">: " + message					




def listen_thread(listen_socket):
	while True:
		accept_socket, address_socket = listen_socket.accept()
		t1 = threading.Thread( target=listen_sub_thread, args=(accept_socket,address_socket, ))
	        t1.start()		


def listen_sub_thread(accept_socket,address_socket):
	while True:
		listen_data = accept_socket.recv(4096)
		if(listen_data.startswith('peerticket1')):
			response_type, response= listen_data.split('***',1)
			iv, ciphertext, tag, additional_authenticated_data = response.split("***",3)
			try:
				decryptedticket = symmetric_decryptServermsg(dhClient_sharedkey[0:32],additional_authenticated_data,iv,ciphertext,tag)
			except:
				print "Error in symmetric decryption!!!"
			timestamp, ticket_timestamp, client_username, ticket_username, ticket_IP, ticket_strport, ticket_clientbytepublickey = decryptedticket.split("***",6)
			ticket_clientpublickey = load_pem_public_key(ticket_clientbytepublickey, backend=default_backend())
			timestamp = get_timestamp()
			try:
				peer_auth2 = asymmetric_encryption(ticket_clientpublickey, client_username+'***'+ticket_username+'***'+ticket_timestamp+'***'+timestamp)
			except:
				print "Error in asymmetric encryption!!!"
			d2 = pyDH.DiffieHellman()
			peer_DH_public_key = d2.gen_public_key()
			try:
				signed_peer_DH_public_key = sign_message(client_private_key, str(peer_DH_public_key))
			except:
				print "Error in symmetric encryption!!!"
			accept_socket.send('peerticket2' +'***'+ peer_auth2 + '***'+signed_peer_DH_public_key+'***'+str(peer_DH_public_key))

		if(listen_data.startswith('peerticket3')):
			responsetype, iv, ciphertext, tag, additional_authenticated_data3, signed_peer2_DH_public_key, peer2_DH_public_key = listen_data.split('***',6)
			if(verifySignature(ticket_clientpublickey,signed_peer2_DH_public_key, peer2_DH_public_key)):
				peer_sharedkey = d2.gen_shared_key(long(peer2_DH_public_key))
				try:
					decryptedmessage = symmetric_decryptServermsg(peer_sharedkey[0:32],additional_authenticated_data3,iv,ciphertext,tag)
				except:
					print "Error in symmetric decryption!!!"
				timestamp, nounce= decryptedmessage.split('***',1)
				if (verifyTimestamp(timestamp)):
					accept_socket.send('peerticket4' +'***'+ nounce)
					activeuserslist.append((client_username,peer_sharedkey[0:32],accept_socket))
					authclientlist.append(client_username)
				

		if(listen_data.startswith('message')):
			responsetype, iv, ciphertext, tag, associated_data, signature, hashofmessage = listen_data.split("***",6)
			try:
				decryptedmessage = symmetric_decryptServermsg(peer_sharedkey[0:32], associated_data, iv, ciphertext, tag)
			except:
				print "Error in symmetric decryption!!!"	
			message, timestamp, username2 = decryptedmessage.split('***', 2)
			
			if(verifySignature(ticket_clientpublickey,signature, hashm(message)) and verifyTimestamp(timestamp)):
				# verify timestamp and then print
				if (message == 'logout'):
					for authuserobject in activeuserslist:
						if username2 in authuserobject:
							activeuserslist.remove(authuserobject)
							authclientlist.remove(username2)		
				else:
					print "<" + username2 + ">: " + message			




def receive_thread(client_socket, listening_socket,):
	while True:
		global activeUserlist
		global logoutnounce
		response = client_socket.recv(4096)		
		if response.startswith('listresponse'):	
			
			responsetype,iv,ciphertext,tag,addn_data,dnp = response.split("***",5)
			try:
				decryptedserver_Optionresponse = symmetric_decryptServermsg(dhClient_sharedkey[0:32],addn_data,iv,ciphertext,tag)
			except:
				print "Error in symmetric decryption!!!"
			activelist,timestamp = decryptedserver_Optionresponse.split("***",1)
			if (verifyTimestamp(timestamp)):
				activeUserlist = pickle.loads(activelist)
				if(dnp == '0'):
					if(activeUserlist != []):
						print "\nlist of active users:"
						for users in activeUserlist:				
							print '\t'+users
					else:
						print "No active users!!!"
			else:
				print "Error in verifying timestamp. Exiting Application"		
				sys.exit()
	
		if response.startswith('ticketresponse'):
			ticket_to_a, ticket = response.split(":::",1)
			responsetype,iv,ciphertext,tag, additional_authenticated_data = ticket_to_a.split("***",4)
			try:
				decryptedticket_to_a = symmetric_decryptServermsg(dhClient_sharedkey[0:32],additional_authenticated_data,iv,ciphertext,tag)
			except:
				print "Error in symmetric encryption!!!"
			timestamp, ticket_timestamp, clientusername, ticket_Username, ticket_IP, ticket_port, ticket_clientbytepublickey = decryptedticket_to_a.split("***",6)
			ticket_socket = socket.socket()         # Create a socket object
			ticket_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			ticket_socket.connect((ticket_IP, int(ticket_port)))
			t2 = threading.Thread( target=peer_thread, args=(ticket_socket,ticket_clientbytepublickey, ))
			t2.start()
			ticket_socket.send('peerticket1' +'***'+ ticket)

		
		if response.startswith('logout'):
			responsetype,iv,ciphertext,tag,additional_authenticated_data = response.split("***",4)
			try:
				decryptedlogout_to_a = symmetric_decryptServermsg(dhClient_sharedkey[0:32],additional_authenticated_data,iv,ciphertext,tag)
			except:
				print "Error in symmetric decryption!!!"
			timestamp, nounce = decryptedlogout_to_a.split("***",1)
			if (nounce == logoutnounce):
				for peerobject in activeuserslist:
										
					user, key, peersocket = peerobject[0], peerobject[1],peerobject[2]
					additional_authenticated_data = b'message'
					plaintext = 'logout' + '***' + get_timestamp() + '***' + username
					try:				
						iv, ciphertext, tag = encrypt(key, plaintext, additional_authenticated_data)
						signature_hash = sign_message( client_private_key,hashm('logout'))
					except:
						print "Error in symmetric encryption!!!"
					peersocket.send('message'+'***'+iv +'***'+ ciphertext+'***'+ tag+'***'+additional_authenticated_data +'***'+signature_hash+'***'+hashm('logout'))

				print "logout successfull!"

				os._exit(1)

		if response.startswith('Error'):
			print response

if __name__ == "__main__":
	try:
		try:	
			client_socket = socket.socket()         # Create a socket object
			client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			client_socket.connect((host, port))

		except:
			print "Server is offline! Try again later!"
			os._exit(1)
		global dhClient_sharedkey
		listening_socket = socket.socket()         # Create a listening object
		listening_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		# Get another address for listening , finding a new freeport to where client listens incoming peer connections
		listening_address = ('localhost', 0)
		listening_socket.bind(listening_address)
		listening_socket.listen(5)
		listeningsocketdetails=listening_socket.getsockname()

		challenge = client_socket.recv(1024)
		bits_118, hash_of_challenge = challenge.split('***',1)	
		challenge_response = break_challenge(bits_118, hash_of_challenge)
		server_public_key = load_server_public_key()
		client_private_key, client_public_key = generate_asymmetric_key()
		d1 = pyDH.DiffieHellman()
		client_DH_public_key = d1.gen_public_key()
		try:
			signed_DH_public_key = sign_message(client_private_key, str(client_DH_public_key))
		except:
			print "Error in symmetric encryption!!!"
		username = raw_input("username: ")
		password = getpass.getpass()	

		timestamp = get_timestamp()
		hash_of_password = hashm(password)
		# symmetric encrypt the data server_public_key, timestamp+'***'+username+'***'+hash_of_password+'***'+str(client_public_key) and assymetric encrypt the key

		symmetric_key = os.urandom(32)
		pem = client_public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
		plaintext = timestamp+'***'+username+'***'+hash_of_password+'***'+pem
		additional_authenticated_data = b'login'
		try:
			iv,ciphertext, tag = encrypt(symmetric_key, plaintext, additional_authenticated_data)
			symmetric_key = asymmetric_encryption(server_public_key, symmetric_key)
		except:
			print "Error in symmetric encryption!!!"
		client_socket.send(challenge_response+'***'+signed_DH_public_key+'***'+symmetric_key+'***'+str(client_DH_public_key) +'***'+iv +'***'+ ciphertext+'***'+ tag+'***'+ additional_authenticated_data)
		server_Response = client_socket.recv(4096)
		if "Error" not in server_Response:
			server_signed_DH_public_key,server_DH_public_key, iv,ciphertext,tag,addn_data = server_Response.split("***",5)
			verifySignature(server_public_key,server_signed_DH_public_key,server_DH_public_key)
			dhClient_sharedkey = d1.gen_shared_key(long(server_DH_public_key))
			try:			
				decryptedServerMessage = symmetric_decryptServermsg(dhClient_sharedkey[0:32],addn_data,iv,ciphertext,tag)
			except:
				print "Error in symmetric encryption!!!"
			nounce,timestamp = decryptedServerMessage.split("***",1)
			client_socket.send(nounce+'***'+str(listeningsocketdetails[1]))
			server_authStatus = client_socket.recv(4096)
			if "Error" not in server_authStatus:	
				print server_authStatus	
			else:
				print server_authStatus
				os._exit(1)
		else:
			print server_Response
			os._exit(1)
	
	
		t = threading.Thread( target=receive_thread, args=(client_socket, listening_socket, ))
		t.start()
		t1 = threading.Thread( target=listen_thread, args=(listening_socket, ))
		t1.start()


		print "\nlist : Get List of Active Users\nsend <username> <message>: Sends message to user\nChoose Your Option"	

		while True:
			client_Option = sys.stdin.readline()
			client_Option = client_Option.strip('\n')
			if (client_Option == 'list') :
				get_ActiveUserList(username,client_Option,'0') 			
				
		
			elif (client_Option.startswith('send')):
				try:				
					option, username1, message = client_Option.split(' ',2)
					if username1 in authclientlist:
				
						for userobject in activeuserslist:
							if(username1 in userobject):
								user, key, socket1 = userobject[0], userobject[1],userobject[2]
								additional_authenticated_data = b'message'
								plaintext = message + '***' + get_timestamp() + '***' + username
								try:
									iv, ciphertext, tag = encrypt(key, plaintext, additional_authenticated_data)
									signature_hash = sign_message( client_private_key,hashm(message))
								except:
									print "Error in signing message!!!"
								socket1.send('message'+'***'+iv +'***'+ ciphertext+'***'+ tag+'***'+additional_authenticated_data +'***'+signature_hash+'***'+hashm(message))

					else:
						 
						get_ActiveUserList(username,'list','1')
				
						onetime_message = message
						print "Requesting Ticket for: " + username1
						plaintext = username+'***'+ username1 + '***' + get_timestamp()			
						additional_authenticated_data = b'ticket'
						try:				
							iv,ciphertext,tag = encrypt(dhClient_sharedkey[0:32], plaintext, additional_authenticated_data)
						except:
							print "Error in symmetric encryption!!!"					
						client_socket.send(iv +'***'+ ciphertext+'***'+ tag+'***'+ additional_authenticated_data)
				except:
					print "Usage: send <username> <message>"
			elif (client_Option == 'logout'):
				global logoutnounce
				logoutnounce = os.urandom(16)
				plaintext = username + '***' + get_timestamp() +'***'+ logoutnounce		
				additional_authenticated_data = b'logout'
				try:
					iv,ciphertext,tag = encrypt(dhClient_sharedkey[0:32], plaintext, additional_authenticated_data)
				except:
					print "Error in symmetric encryption!!!"
				client_socket.send(iv +'***'+ ciphertext+'***'+ tag+'***'+ additional_authenticated_data)
				
						
			else:
				print "Invalid option! Try again!"	

	except:
		print "Critical error!! Exiting application!!"
		os._exit(1)
