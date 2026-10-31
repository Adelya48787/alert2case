.PHONY: up up-full down ps logs reset doctor simulate migrate restart-worker
up:        ## əsas servislər
	docker compose up -d
up-full:   ## + TheHive steki
	docker compose --profile thehive up -d
down:
	docker compose --profile thehive down
ps:
	docker compose --profile thehive ps
logs:
	docker compose logs -f --tail=100
reset:     ## DİQQƏT: bütün məlumatı silir
	docker compose --profile thehive down -v
doctor:
	tools/doctor.sh

simulate:   ## 36 alert-i API-yə göndər
	python tools/simulator.py --rate 2
migrate:    ## bazaya miqrasiyaları tətbiq et
	docker compose run --rm api alembic upgrade head
restart-worker:
	docker compose restart worker
