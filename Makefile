.PHONY: up up-full down ps logs reset doctor simulate migrate restart-worker up-obs reset-data up-prod down-prod prod-check
up:        ## əsas servislər
	docker compose up -d
up-full:   ## + TheHive steki
	docker compose --profile thehive up -d
down:
	docker compose --profile thehive --profile obs down
ps:
	docker compose --profile thehive --profile obs ps
logs:
	docker compose logs -f --tail=100
reset:     ## DİQQƏT: bütün məlumatı silir
	docker compose --profile thehive --profile obs down -v
doctor:
	tools/doctor.sh

simulate:   ## 36 alert-i API-yə göndər
	python tools/simulator.py --rate 2
migrate:    ## bazaya miqrasiyaları tətbiq et
	docker compose run --rm api alembic upgrade head
restart-worker:
	docker compose restart worker
up-obs:     ## + Prometheus və Grafana
	docker compose --profile obs up -d
reset-data: ## DİQQƏT: alert, case, audit məlumatını silir (cədvəllər qalır)
	docker compose exec -T postgres psql -U soc -d alert2case -c "TRUNCATE alerts, audit_log CASCADE"
	docker compose exec -T redis redis-cli FLUSHDB
	# case faylları container-də root ilə yaradılır: host istifadəçisi silə bilmir, container silir
	docker compose exec -T worker sh -c 'rm -rf /code/var/cases /app/var/cases'   # dev: /code, prod: /app
	docker compose restart worker

PROD = docker compose -f docker-compose.yml -f docker-compose.prod.yml
up-prod:    ## api və worker production image ilə (6.5)
	$(PROD) up -d --build api worker
down-prod:  ## api və worker-i dev image-ə qaytar
	docker compose up -d --build --force-recreate api worker
prod-check: ## production image və container-lərin yoxlaması (6.5)
	tools/prod_check.sh
