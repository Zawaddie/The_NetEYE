import os
from flask import Flask, render_template, session, redirect, url_for, request
# from flask_sqlalchemy import SQLAlchemy
# from flask_mail import Message
# from flask_bootstrap import Bootstrap
# from flask_wtf.csrf import CSRFProtect

# from flask_mail import Mail

app = Flask(__name__)
# bootstrap = Bootstrap(app)

# # app.config.from_object('settings')
# app.secret_key = os.urandom(24)
# app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# app.config['MAIL_SERVER'] = 'smtp.gmail.com'
# app.config['MAIL_PORT'] = 587
# app.config['MAIL_USE_TLS'] = True
# app.config['MAIL_USE_SSL'] = False
# app.config['MAIL_USERNAME'] = 'puritynyakundi00@gmail.com'
# app.config['MAIL_DEFAULT_SENDER'] = ('purity nyakundi', 'puritynyakundi00@gmail.com')
# app.config['MAIL_PASSWORD'] = "eoucuqmrkhhhjulp"
# app.config['OPS_TEAM_MAIL'] = 'puritynyakundi00@gmail.com'
# csrf = CSRFProtect(app)
# mail = Mail(app)



# # send email function
# def send_email(recipient, email_subject, email_body):
#     """
#       function: send email
#        :param : recipient - deliver the email to this recipient
#                 email_subject - subject of the email
#                 email_body - Body of the mail..

#     """
#     message = Message(email_subject, recipients=[recipient])
#     message.body = email_body
#     mail.send(message)






# message object mapped to a particular URL ‘/’
@app.route("/")
def index():
    return "Get Method Requested"

@app.route("/predictions", methods= ['POST'])
def index2():
     if request.method =="POST":
        data = request.form.to_dict()
        #data = request.get_json()
        print(data)
        return jsonify({"text":"text"})
     return jsonify({"text":None, "label":None})

#     try:
#         send_email("stiveckamash@gmail.com", "hi there are you there", "<h1>sending form this wotlsnfhlk</h1>")
#         return 'Sent'
#     except Exception as e:
#         return f"Eroor  as  {e}"

if __name__ == '__main__':
    app.run(host="127.0.0.1", port="8000",debug=True)