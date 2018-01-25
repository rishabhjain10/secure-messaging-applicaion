# secure-messaging-applicaion
# Installation steps
1. Make sure the following files are available in our working folder:  
   - Key files for server:  
     - Server Public Key  
     - Server Private Key  
     - ChatConf.conf  
   - Key files for client:  
     - Server Public Key  
     - ChatConf.conf  

2. Make sure pyDH is  installed on both the machines  
To install pyDH, simply  
```
pip install pyDH  
```  
For details please refer:https://github.com/amiralis/pyDH  

3. Creating username and passwords  
To register a new user run createPasswd.py present in server folder
```
python createPasswd <newusername> <password>
```

# Usage: Server
```
python chatServer.py
```
Initializes the server on port and ip mentioned in the config

# Usage: Client
```
python chatClient.py
```
Initializes the client and connect to server port and ip mentioned in the config

# Usage: Commands accepted on client
```list```  
Gives the list of active users

```send <username> <message>```  
Sends message to the username specified

```logout```  
Logouts the client

