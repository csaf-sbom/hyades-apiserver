# Local development
How to get it up and running locally for development
## Launch hyades components
This will include workers for both mirroring and scanning tasks
```
git clone git@github.com:csaf-sbom/hyades.git
```
Run db and kafka/redpanda
```
docker compose up -d
```

For *first-run*, build it once!
```
mvn package -DskipTests -Dcheckstyle.skip
```

Start local development
```
mvn quarkus:dev -Dcheckstyle.skip
```


mvn -pl mirror-service quarkus:dev -Dcheckstyle.skip
mvn -pl vulnerability-analyzer quarkus:dev -Dcheckstyle.skip


## Launch apiserver (this repository)
This will provide backend functionality to the frontend and coordinate worker tasks
```
git clone git@github.com:csaf-sbom/hyades-apiserver.git
```

Run locally using fhgrun.sh: maven jetty plugin+config
```
./fhgrun.sh
```

NOTE: MISSING CREATE STATEMENT FOR CSAF_MANAGEMENT and ._READ rights!

## Launch frontend
Clone frontend
```
git clone git@github.com:csaf-sbom/hyades-frontend.git
```

Run the frontend **AFTER** starting services and apiserver, it will chose the next available port automatically. 

**NOTE** if starting this first, it will claim ports required by apiserver, therefore start it last!
```
npm start
```