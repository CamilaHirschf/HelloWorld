from waitress import serve
import logging
import app

app_instance = app.create_app()
serve(app_instance, host='0.0.0.0', port=5000, url_scheme='https')


logging.basicConfig(filename='./log.txt', level=logging.DEBUG)



