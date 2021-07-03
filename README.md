# Tusky Identity service
## For developers
### Start Service
```
docker compose up --build
```
### Run tests
```
bash tests.sh
```
### Manage database
Enter the container running the service `backend`;
if you need to, get the names of running containers using `docker ps`

It should return something like this:
```
CONTAINER ID   IMAGE          COMMAND                  CREATED         STATUS         PORTS                                       NAMES
fa9c4e330ea2   0e8a35bfc485   "/start-reload.sh"       5 minutes ago   Up 2 seconds   0.0.0.0:8007->80/tcp, :::8007->80/tcp       users_backend_1
709456b5f3be   ed45d5bb6847   "docker-entrypoint.s…"   5 minutes ago   Up 2 seconds   5432/tcp                                    users_db_1
```
In our example, the container running `backend` is named `users_backend_1`, so the command to enter the container is `docker exec -it users_backend_1 /bin/bash`.

Then, you can run `python manage.py` followed by one of the following arguments:
  - `initdb`
  - `dropdb`
  - `resetdb`
