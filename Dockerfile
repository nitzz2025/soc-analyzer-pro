FROM python:3.11-slim
RUN useradd -m socuser
WORKDIR /home/socuser
COPY . .
RUN pip install --no-cache-dir rich
USER socuser
CMD ["python", "soc_analyzer_pro/src/main.py"]