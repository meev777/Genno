FROM python:3.12-slim
RUN useradd -r -u 10001 genno
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir asyncssh
COPY genno ./genno
USER 10001
EXPOSE 2222
CMD ["python","-m","genno.ssh.server","--host","0.0.0.0","--port","2222","--log","/data/events.jsonl"]
