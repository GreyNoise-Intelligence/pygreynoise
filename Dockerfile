FROM python:3.7-alpine as builder
COPY . /app
WORKDIR /app
RUN pip install -r requirements/common.txt && python3 setup.py bdist_wheel

FROM python:3.7-alpine
COPY --from=builder /app/dist/*.whl /app/
WORKDIR /app
RUN pip install /app/*.whl
