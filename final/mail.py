from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib

# vxjpxhjlqzbwycek
#
def send_email(subject,email_address,messageToSend):
    msg = MIMEMultipart()
    message = messageToSend
    # user_id = ''
    # msg['From'] = "zeddiezawadi@gmail.com"
    user_id = 'hkvdmkomzzvlvfed'
    msg['From'] = "engraced.tech.solutions@gmail.com"
    msg['To'] = email_address
    msg['Subject'] = subject

    msg.attach(MIMEText(message, 'plain'))
    try:
        server = smtplib.SMTP('smtp.gmail.com: 587')
        server.starttls()
        server.ehlo()
        server.login(msg['From'], user_id)
        server.sendmail(msg['From'], msg['To'], msg.as_string())
        server.quit()
        print('yes')
    except Exception as e:
        print(e)

if __name__ == "__main__":
    send_email("Threat Detected!" , 'zeddieburu87@gmail.com' , """Alerting you of detected malicious traffic
    
     Source Ip       :
     Source Port     :

     Destination IP  :
     Destination Port:

     Flag            : 
     TimeStamp       :
        """)


# send_email("hi" , 'zeddiezawadi@gmail.com' , "heloooo")
