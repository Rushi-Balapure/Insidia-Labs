FROM python:3.12-slim@sha256:dddfd7e07f9d15aeeca61529320492139d21cac7f0070c00609243e51e4e0016
WORKDIR /opt/fixture
COPY insidia /opt/fixture/insidia
ENV PYTHONPATH=/opt/fixture
ENV PYTHONDONTWRITEBYTECODE=1
USER nobody
CMD ["python", "-m", "insidia.serve"]
