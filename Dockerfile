FROM python:3.7-alpine as builder
COPY . /app
WORKDIR /app
RUN python3 setup.py sdist bdist_wheel
FROM python:3.7-alpine
COPY --from=builder /app/dist/*.whl /app/
WORKDIR /app
RUN pip install /app/*.whl 


