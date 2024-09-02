# To install packages including opendp_polars and opendp_logger 
FROM python:3.11-bullseye as gramine_ratls_python_base

# To install missing packages
COPY ./example/requirements.txt /requirements.txt
RUN pip install --no-cache-dir --upgrade -r requirements.txt

WORKDIR /code
FROM gramine_ratls_python_base AS gramine_ratls_python_demo
COPY ./src/ /code/
COPY ./example/src/ /code/
COPY ./LICENSE /code/LICENSE
CMD ["python", "uvicorn_serve.py"]