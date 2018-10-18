FROM python:3

RUN pip install --upgrade pip && \
    pip install flask pyotp qrcode

COPY authserver.py /
COPY templates /templates/
WORKDIR /
CMD ["./authserver.py"]