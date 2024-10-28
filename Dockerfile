FROM python:3.12

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
COPY . .
RUN pip install -r requirements.txt
ENTRYPOINT ["python3", "analyze.py"]