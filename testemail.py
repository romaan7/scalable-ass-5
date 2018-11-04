import smtplib

gmail_user = 'rom@tcd.ie'  
gmail_password = 'namor1TCD'

sent_from = gmail_user  
to = ['romaan7@gmail.com', 'shaikhr@tcd.ie']  
subject = 'OMG Super Important Message'  
body = 'Hey, what'

email_text = """\ 
From: %s  
To: %s  
Subject: %s

%s
""" % (sent_from, ", ".join(to), subject, body)

 
server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
server.ehlo()
server.login(gmail_user, gmail_password)
server.sendmail(sent_from, to, email_text)
server.close()
print 'Email sent!'