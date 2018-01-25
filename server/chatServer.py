import socket, select, string, sys, os, random, datetime, codecs, pyDH, pickle, threading
from datetime import datetime, date, time, timedelta
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key



def client_thread(client_socket,addr):
	try:
		print 'Got connection from', addr
		challenge = generateCookie(addr[0],cookie_Map)
		client_socket.send(challenge)
		client_response = client_socket.recv(4096)
		challenge_response,signed_DH_public_key,clientmsg_symmetric_key,client_DH_public_key,iv,ciphertext,tag,additional_authenticated_data = client_response.split("***",7)

		if(verifyChallengeResponse(challenge_response, addr[0],cookie_Map)):
			#decryt sout[2] to obtain timestamp, username, hashof password, client public key
			try:
				decrypted_symmetrickey =  decryptClientMessagekey(clientmsg_symmetric_key)
				decryptedClientMessage = symmetric_decryptClientmsg(decrypted_symmetrickey,additional_authenticated_data,iv,ciphertext,tag)
			except:
				print "Error in asymmetric decryption!!!"

			timestamp,username,hashofpwd,clientbytepublickey = decryptedClientMessage.split("***",3)
			clientpublickey = load_pem_public_key(clientbytepublickey, backend=default_backend())
			#if timestamp is morethan 2 - abort connection and very hash of password
			if ( verifyTimestamp(timestamp) and verifyPwdhash(username,hashofpwd) ):
				#register user to active user and store username and public key in list
				if username not in ACTIVEUSER_LIST:
					
					verifySignature(clientpublickey,signed_DH_public_key,client_DH_public_key) 
					#check return type and criteria to check
					dhServer = pyDH.DiffieHellman()
					server_DH_public_key = dhServer.gen_public_key()
					dhServer_sharedkey = dhServer.gen_shared_key(long(client_DH_public_key))
					try:
						signed_DH_public_key = sign_message(server_private_key, str(server_DH_public_key))
					except:
						print "Error in signing message!!!"

					nounce = os.urandom(16)
					timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
					addn_data = b'auth'
					try:
						iv,ciphertext,tag = encrypt(dhServer_sharedkey[0:32], nounce + "***"+ timestamp, addn_data)
						client_message = signed_DH_public_key+"***"+str(server_DH_public_key)+"***"+iv+"***"+ciphertext+"***"+tag+'***'+addn_data
					except:
						print "Error in symmetric encryption!!!"

					#verify signature and retrive the DH public key of client, send signed dh cont, prepare session key
					client_socket.send(client_message)
					client_nounceresponse1 = client_socket.recv(4096)
					client_nounceresponse, listening_port= client_nounceresponse1.split("***",1)
					if(client_nounceresponse == nounce):
						client_socket.send("Login Succesfull!")
						ACTIVEUSER_LIST.append(username)
						ACTIVEUSER_DATALIST.append((username,addr[0], listening_port,clientpublickey,dhServer_sharedkey[0:32]))
						print username + " logged on from <" + addr[0] + ":" + str(addr[1]) + ">"
						
						while True:
							client_option = client_socket.recv(4096)
							iv,ciphertext,tag,additional_authenticated_data = client_option.split("***",4)
							
							if(additional_authenticated_data == b'list'):
								try:
									decrytedclient_option = symmetric_decryptClientmsg(dhServer_sharedkey[0:32],additional_authenticated_data,iv,ciphertext,tag)
								except:
									print "Error in symmetric decryption!!!"

								dnp, clientusername,timestamp = decrytedclient_option.split("***",2)
								if((clientusername in ACTIVEUSER_LIST) and verifyTimestamp(timestamp)):
									
									timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
									addn_data = b'ticket'
									listtosend = list(ACTIVEUSER_LIST)
									listtosend.remove(clientusername)	
									try:
										iv,ciphertext,tag = encrypt(dhServer_sharedkey[0:32], pickle.dumps(listtosend) + "***"+ timestamp, addn_data)
									except:
										print "Error in symmetric encryption!!!"

									client_socket.send('listresponse'+'***'+iv+'***'+ciphertext+'***'+tag+'***'+addn_data +"***"+dnp)

							#loop to grant ticket
							if(additional_authenticated_data == b'ticket'):
								try:
									decrytedclient_option = symmetric_decryptClientmsg(dhServer_sharedkey[0:32],additional_authenticated_data,iv,ciphertext,tag)
								except:
									print "Error in symmetric decryption!!!"

								clientusername,ticket_Username,timestamp = decrytedclient_option.split("***",2)
								if((clientusername in ACTIVEUSER_LIST) and verifyTimestamp(timestamp) and (ticket_Username in ACTIVEUSER_LIST) and (clientusername != ticket_Username) ):
									#generate ticket for ticket_Username
									timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
									now_plus_10 = datetime.now() + timedelta(minutes = 10)
									ticket_timestamp = now_plus_10.strftime('%Y-%m-%d %H:%M:%S')
									addn_data = b'ticket2'

									for ticket_Usernameitem in ACTIVEUSER_DATALIST:
   										if ticket_Username in ticket_Usernameitem:
       											ticket_IP, ticket_port, ticket_clientpublickey,ticket_sharedkey = ticket_Usernameitem[1], ticket_Usernameitem[2], ticket_Usernameitem[3], ticket_Usernameitem[4]
											ticket_clientbytepublickey = ticket_clientpublickey.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
											try:
												iv1,ciphertext1,tag1 = encrypt(dhServer_sharedkey[0:32],  timestamp+"***"+ticket_timestamp+"***"+clientusername+"***"+ticket_Username+"***"+ticket_IP+"***"+str(ticket_port)+"***"+ticket_clientbytepublickey, addn_data)								
					
												iv_ticket,ciphertext_ticket,tag_ticket = encrypt(ticket_sharedkey,  timestamp+"***"+ticket_timestamp+"***"+clientusername+"***"+ticket_Username+"***"+addr[0]+"***"+str(listening_port)+"***"+clientbytepublickey, addn_data)
											except:
												print "Error in symmetric encryption!!!"

											client_socket.send('ticketresponse'+'***'+iv1+'***'+ciphertext1+'***'+tag1+'***'+addn_data+":::"+iv_ticket+'***'+ciphertext_ticket+'***'+tag_ticket+'***'+addn_data)
								
								else:
									client_socket.send("Error::Requested Client Not Online!!")
							#loop to logout client
							if(additional_authenticated_data == b'logout'):
								try:
									decrytedclient_option = symmetric_decryptClientmsg(dhServer_sharedkey[0:32],additional_authenticated_data,iv,ciphertext,tag)
								except:
									print "Error in symmetric decryption!!!"

								clientusername,timestamp, nounce = decrytedclient_option.split("***",2)	
								if((clientusername in ACTIVEUSER_LIST) and verifyTimestamp(timestamp)):
									ACTIVEUSER_LIST.remove(clientusername)
									for ticket_Usernameitem in ACTIVEUSER_DATALIST:
   										if clientusername in ticket_Usernameitem:
											ACTIVEUSER_DATALIST.remove(ticket_Usernameitem)

									addn_data=b'logout'
									plaintext = get_timestamp() +'***'+ nounce
									try:
										iv,ciphertext,tag = encrypt(dhServer_sharedkey[0:32],  plaintext, addn_data)
									except:
										print "Error in symmetric encryption!!!"

									client_socket.send('logout'+'***'+iv+'***'+ciphertext+'***'+tag+'***'+addn_data)
									print clientusername + " logged out from <" + addr[0] + ":" + str(addr[1]) + ">"
									sys.exit()
					else:
						client_socket.send("Error::Login Unsuccesfull! Please try again.")
						client_socket.close()				

				else: 
					print "Error::User already logged in!"
					client_socket.send("Error::User already logged in!")
					client_socket.close()
			else: 
				print "Error::Login failed!"
				client_socket.send("Error::Login failed!")
				client_socket.close()
			 
			
		 
	except:
		pass	

	client_socket.close()

#function to generate cookie
def generateCookie(client_address,cookie_Map):
	x = bin(random.getrandbits(128))
	bits_128 = str(x[2:130]).rjust(128,'a')
	clientChallenge = bits_128 + client_address
	digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
	digest.update(clientChallenge)
	cookie_Hash = digest.finalize()
	initial_Bits = bits_128[0:118]
	secret_Bits = bits_128[118:128]
	cookie_Map[client_address] = secret_Bits
	deli = "***"
	final_Cookie = initial_Bits + deli + cookie_Hash
	return final_Cookie

#function to verify cookie
def verifyChallengeResponse(client_CookieResponse,client_address,cookie_Map):
	
	secret_Bits = cookie_Map[client_address]
	if(secret_Bits == client_CookieResponse):
		return True 
	else:
		return False

#function to decryptClientLoginMessage cookie
def decryptClientMessagekey(client_Message):

	decryptedClientMsg = server_private_key.decrypt(
			client_Message,
			padding.OAEP(
				    mgf=padding.MGF1(algorithm=hashes.SHA1()),
				    algorithm=hashes.SHA1(),
				    label=None))
	return decryptedClientMsg

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

#function to verify clients pwdhash
def verifyPwdhash(client_username, client_pwdhash):

	separator="***"
	fileIN = open("passwd.txt", "r")
	data = fileIN.readlines()
	hexlify = codecs.getencoder('hex')
	client_hexpwdhash= hexlify(client_pwdhash)[0]
	for line in data:
		line = line.strip('\n')
		sout=line.split(separator)
		if(client_username == sout[0]):
			if(client_hexpwdhash == sout[1]):				
				return True	
	return False

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
def symmetric_decryptClientmsg(key, associated_data, iv, ciphertext, tag):
    decryptor = Cipher(algorithms.AES(key),modes.GCM(iv, tag),backend=default_backend()).decryptor()
    decryptor.authenticate_additional_data(associated_data)
    return decryptor.update(ciphertext) + decryptor.finalize()

#function symmetric encryption
def encrypt(key, plaintext, additional_authenticated_data):
    iv = os.urandom(16)
    encryptor = Cipher(algorithms.AES(key),modes.GCM(iv),backend=default_backend()).encryptor() # AES_GCM mode with 256 bit symmetric key
    encryptor.authenticate_additional_data(additional_authenticated_data) # Authenticaed data in our case its hash(plain_message)
    # sign hash of message with private key
    m = plaintext
    ciphertext = encryptor.update(m) + encryptor.finalize()
    return (iv, ciphertext, encryptor.tag)

#function to sign message
def sign_message(key, message):
    signer = key.signer(padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
    signer.update(message)
    signature = signer.finalize()
    return signature

def get_timestamp() :
    	return datetime.now().strftime('%Y-%m-%d %H:%M:%S')



if __name__ == "__main__":
	
	try:
		ACTIVEUSER_LIST = [] #List to maintain active user username
		ACTIVEUSER_DATALIST = [] #List to maintain active user data
		cookie_Map = {}
		server_socket = socket.socket()         # Create a socket object
		server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		try:		
			f = open('chatConf.conf', 'r')
			for line in f:
				if 'Server' in line :
					server, ip, port = line.split(":",2)
					host = ip 
					port = int(port)
		except:
			print "Config File missing! Please make sure configuration file is in same folder!"
			os._exit(1)
		server_address = (host, port)
		server_socket.bind((host, port))        # Bind to the port
	
	
	    	with open("server_private_key.pem", "rb") as key_file:
	     		server_private_key = serialization.load_pem_private_key(
		    		key_file.read(),
				password=None,
		    		backend=default_backend())
	    	server_public_key = server_private_key.public_key()


		server_socket.listen(10)               # Now wait for client connection.
		print 'Server Initialized on %s port %s' % server_address
		while True:
			client_socket, addr = server_socket.accept()     # Establish connection with client.
			t = threading.Thread( target=client_thread, args=(client_socket, addr, ))
			t.start()
	except:
		print "Critical error!! Exiting server!!"
		server_socket.close()		
		os._exit(1)



    
