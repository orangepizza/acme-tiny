#!/usr/bin/env python3
from asyncio import open_connection
import email
from email import message, utils
from email.policy import Policy
from email.header import decode_header
import smtplib, imaplib
import configparser, ssl
from pathlib import Path
#try import dkimpy for dkim check
dkimpyexsit = True
try:
    import dkim
except ImportError:
    dkimpyexsit = False

def checkmailsign(mail:bytes):
    # return early if dkim verified, if not imported it will pass
    if dkimpyexsit == False:
        if dkim.verify(mail):
            return True
    #TODO actually check need header that must be signed by RFC8823

    return False


#ssl mode (explict, starttls, none)
def open_imap_connection(config: configparser.ConfigParser,verbose=False):
    # Connect to the server
    hostname = config.get('imap', 'hostname')
    port = config['imap']['port']
    connection = None
    context= ssl.create_default_context()
    tlsmod = config['imap']['tlsmod']
    #some major mailing server had weak DH key, lowering security level
    context.set_ciphers('DEFAULT@SECLEVEL=1')
    #if not explict TLS(starttls or plaintext) we start planetext connection
    if str.upper(tlsmod) != "TLS":
        if verbose:
            print('opens plaintext connection to')
        connection = imaplib.IMAP4(hostname,port)
        # if starttls we start tls here
        if str.lower(tlsmod) == "starttls":
            ok, _ = connection.starttls(context)
            if ok != 'OK':
                print("error starting starttls")
    else:
        if verbose:
            print('Connecting to', hostname, "with explict TLS") 
        connection = imaplib.IMAP4_SSL(host= hostname, port= config.get('imap','port'), ssl_context= context)


    #Login
    username = config.get('imap', 'username')
    password = config.get('imap', 'password')
    if verbose:
        print('Login as', username)
    connection.login(username, password)
    status, answer = connection.select("INBOX")
    if status != 'OK':
        print(f"can't access inbox,{status},{answer}")
    return connection

#this function flushes all mail start with ACME: header and mark all such mail as read
# so we won't have old unseen ACME related mail
# if delete parameter is true, it will delete it from mailbox too.
def flushchallangemail(connection: imaplib.IMAP4, delete:bool = False):
    typ, sr = connection.search(None, 'UNSEEN Subject "ACME: "')
    if typ != "OK":
        return False
    ml = sr[0].split()
    for n in ml:
        connection.store(n, '+FLAGS', '\Seen')
        if delete:
            connection.store(n, '+FLAGS', '\\Delete')
    if delete:
        connection.expunge()
    return True


#we need three thing challange email: subject(token_part1), reply-to, message-id for SHOULD be set for In-Reply-To
#mailforchalange should be mail address of ACME server
def fetchmailtoken(connection: imaplib.IMAP4, mailfrom: str, verifysign = False):
    #search from IMAP server by FROM and have ACME: in subject which given by CA
    typ, searchresult = connection.search(None, f'UNSEEN FROM "{mailfrom}" Subject "ACME: "')
    if typ != "OK":
        print(f"there was Error in serch {searchresult}")
    maillist = searchresult[0].split()
    for num in maillist:
        connection.store(num, '+FLAGS', '\Seen')
        typ, msg = connection.fetch(num, '(RFC822)')
        if typ != "OK":
            #try downloading once again:
            typ, msg = connection.fetch(num, '(RFC822)')
            if typ != "OK":
                #if failed again we skip this email
                print(f"faild to download mail number {num}")
                continue
        msgbody = msg[0][1]
        # if we check sign and it returned false, it fails
        if verifysign and not checkmailsign(msgbody):
            continue
        #now we know this is valid mail from CA, so we can parse needed info from it
        parsedmsg = email.message_from_bytes(msgbody)
        subject, encoding = decode_header(parsedmsg["Subject"])[0]
        if isinstance(subject, bytes):
            # if it's a bytes, decode to str
            subject = subject.decode(encoding)
        #if there isn't reply-to header we should send challange response back to its sender, if not exsit it's mail From as default
        replyto = parsedmsg.get("Reply-to", mailfrom)
        messageid = parsedmsg['message-id']
        print(subject, "\nreplyto\n",replyto,"\nmessageid\n",messageid)
        #Keep mind subject still has ACME: header attached
        return subject, replyto, messageid
    # if we reach here there was no valid mail from CA, so we sleep and restart

def getmailtoken(cfg:configparser.ConfigParser, servermailadr, verifysign: bool):
    with open_imap_connection(cfg, verbose=True) as cnt:
        mailforchallange = cfg['DEFAULT']["mailaddress"]
        #mailname
        return fetchmailtoken(cnt, servermailadr,verifysign)

def sendmail(config:configparser.ConfigParser, mailtosend:message.EmailMessage):
    #connect to server
    print('try to send mail')
    smtpconfig = config['smtp']
    server = None
    if smtpconfig["tlsmod"] != "TLS":
        server = smtplib.SMTP(smtpconfig["hostname"], smtpconfig["port"])
        #if we didn't disable stattls, run starttls
        if smtpconfig["tlsmod"] != "none":
            server.starttls()
    else:
        server = smtplib.SMTP_SSL(smtpconfig["hostname"],smtpconfig["port"], context= ssl.create_default_context())
    #try login now
    server.login(smtpconfig["username"],smtpconfig["password"])
    iferr = server.send_message(mailtosend)
    print(iferr)
    return True

#sendmail return true when it could send mail, otherwise it fails

#craft email object from needed info, keep mine caller of this function has to craft the reponse digest.
def craftmail(token_part1:str,responsedigest:str, reply_to_address:str, message_id, From:str):
    mailtosend = message.EmailMessage()
    mailtosend["In-Reply-To"] = message_id
    if "ACME: " in token_part1: #if subject already has ACME: header, use as-is.
        mailtosend["Subject"] = token_part1
    else: #if client sends raw token-part1 as challangename, we add ACME: header to it
        mailtosend["Subject"] = f"ACME: {token_part1}"
    mailtosend["From"] = From
    mailtosend["to"] = reply_to_address
    mailtosend["date"] = utils.localtime()
    #add needed formatting to mail, email expects \r\n as line sapareater
    mailbody = "-----BEGIN ACME RESPONSE-----\r\n" + responsedigest + "\r\n-----END ACME RESPONSE-----\r\n"
    mailtosend.set_content(mailbody)
    mailtosend.set_charset(charset= 'ascii')
    mailtosend.set_type("text/plain")
    return mailtosend

#we test thing when this file is called directly
if __name__ == '__main__':
    # Read the config file
    config = configparser.ConfigParser()
    config.read('mailconfig.ini')
    mailforchallange = config['DEFAULT']["mailaddress"]
    mockACMEServerMail = "abnoeh@mail.com"
    with open_imap_connection(config, verbose=True) as cd:
        #mailname
        print(cd)
        subject, replyto, msgid = fetchmailtoken(cd, mockACMEServerMail,verifysign= False)
        responsemail = craftmail(subject, "UsEt6isA5keydigest", replyto, msgid, mailforchallange)
        print (responsemail)
        sendmail(config, responsemail)
        