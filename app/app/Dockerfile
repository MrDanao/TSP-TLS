FROM python:3.6.10

RUN apt update && \
    apt upgrade -y && \
    apt install -y \
        default-libmysqlclient-dev \
        net-tools

ENV DIR /tls
ENV FLASK_APP app
ENV FLASK_DEBUG 1

RUN mkdir -p $DIR/$FLASK_APP

WORKDIR $DIR

COPY requirements.txt .

RUN pip install -r requirements.txt

#COPY src/* app/

CMD flask run --host=0.0.0.0 