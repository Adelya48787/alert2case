# Alert schema uyğunluq cədvəli (OCSF / ECS)

Sahə adları OCSF Detection Finding (class_uid 2004) sinfindən götürülüb. Tam OCSF obyekti yox, lazım olan alt çoxluq saxlanılır.

| Bizim sahə | OCSF | ECS |
|---|---|---|
| alert_id | finding_info.uid | event.id |
| title | finding_info.title | rule.name |
| time | time | @timestamp |
| received_at | metadata.logged_time | event.ingested |
| severity_id | severity_id | event.severity |
| source_system | metadata.product.name | observer.type |
| user | actor.user.name | user.name |
| host | device.hostname | host.name |
| observables[] | observables[] | source.ip, url.full, file.hash.sha256 |
| raw | raw_data | event.original |

## Severity uyğunluğu

Bizim `Severity` OCSF `severity_id` ilə eynidir: 0 Unknown, 1 Informational, 2 Low, 3 Medium, 4 High, 5 Critical, 6 Fatal.

## Niyə tam OCSF yox

Tam obyektdə yüzlərlə sahə var və bizə lazım deyil. Sahə adlarını və mənalarını standartdan götürürük. Cədvəl istənilən vaxt tam OCSF-ə çevirməyə imkan verir. Hesabatda "OCSF-uyğun" demək üçün sübut budur.
