# Production image (6.5): iki mərhələ, kiçik ölçü, root olmayan istifadəçi.
# İnkişaf üçün Dockerfile.dev qalır (kod mount olunur, --reload). Bu image-də kod image-in içindədir.

# 1) build: asılılıqlar ayrıca qovluğa quraşdırılır (pip cache və build alətləri son image-ə düşmür)
FROM python:3.12-slim AS build
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# 2) runtime: yalnız quraşdırılmış paketlər və tətbiqin işləməsi üçün lazım olan qovluqlar
FROM python:3.12-slim
# Fayl sistemi read-only-dir: tldextract suffix siyahısını HOME-a yox, /tmp-yə (tmpfs) keşləyir
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 TLDEXTRACT_CACHE=/tmp/tldextract
RUN useradd --create-home --uid 10001 app
WORKDIR /app
COPY --from=build /install /usr/local
COPY alembic.ini ./
COPY migrations/ migrations/
COPY app/ app/
COPY rules/ rules/
COPY context/ context/
# Fayl case backend-i var/cases-ə yazır. Qovluq app istifadəçisinə məxsusdur, named volume ilk dəfə buradan doldurulur.
RUN mkdir -p var/cases && chown -R app:app var
USER app
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health', timeout=2)"
# Bir uvicorn prosesi: Prometheus metrikaları proses daxilində saxlanılır. Yük artsa, container sayını artırın.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
