FROM python:3.12-slim@sha256:dddfd7e07f9d15aeeca61529320492139d21cac7f0070c00609243e51e4e0016
WORKDIR /opt/fixture
COPY insidia /opt/fixture/insidia
ENV PYTHONPATH=/opt/fixture
ENV PYTHONDONTWRITEBYTECODE=1
# The process is inside the sandbox network. 0.0.0.0 is required so other
# containers can connect; the host default in serve.py stays 127.0.0.1.
ENV INSIDIA_FIXTURE_HOST=0.0.0.0
USER nobody
CMD ["python", "-m", "insidia.serve"]
