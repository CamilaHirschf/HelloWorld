FROM python:latest

COPY requirements.txt /
RUN pip3 install --upgrade pip
RUN pip3 install -r /requirements.txt
COPY . /app
WORKDIR /app
RUN chgrp -R 0 /app && \
   chmod -R g=u /app
EXPOSE 8080




CMD ["gunicorn","--config", "gunicorn_config.py", "app:create_app()"]
