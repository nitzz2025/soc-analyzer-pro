# Use slim bullseye for minimal attack surface
FROM python:3.10-slim-bullseye

# Security: Prevent python from buffering logs
ENV PYTHONUNBUFFERED=1

# Security: Set non-root user
RUN groupadd -g 1000 socgroup && useradd -u 1000 -g socgroup -m socuser
USER socuser
WORKDIR /home/socuser/app

# Copy project files
COPY --chown=socuser:socgroup pyproject.toml README.md ./
COPY --chown=socuser:socgroup soc_analyzer_pro/ ./soc_analyzer_pro/

# Install project using the PEP 621 manifest
RUN pip install --no-cache-dir .

# Secure Entrypoint
ENTRYPOINT ["python3", "-m", "soc_analyzer_pro.src.main"]