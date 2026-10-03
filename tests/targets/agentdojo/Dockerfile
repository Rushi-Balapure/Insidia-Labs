FROM python:3.12-slim@sha256:dddfd7e07f9d15aeeca61529320492139d21cac7f0070c00609243e51e4e0016
RUN pip install --no-cache-dir --disable-pip-version-check agentdojo==0.1.35 \
    && python -c "import agentdojo"
ENV PYTHONDONTWRITEBYTECODE=1
USER nobody
CMD ["python", "-c", "import agentdojo, time; time.sleep(10**9)"]
