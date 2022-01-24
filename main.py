from website import create_app
from OpenSSL import SSL
'''
context = SSL.Context(SSL.TLSv1_2_METHOD)
context.use_certificate('mycert.crt')
context.use_privatekey('myprivatekey.key')
'''
app = create_app()

if __name__ == '__main__':
    app.run(debug=True, ssl_context='adhoc')
