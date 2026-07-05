FROM eclipse-temurin:17-jdk

WORKDIR /app

COPY TinferServer.java .
COPY sqlite-jdbc.jar .
COPY slf4j-api.jar .
COPY slf4j-nop.jar .
COPY tinfer.db .

RUN javac TinferServer.java

EXPOSE 8080

CMD ["java", "-cp", ".:sqlite-jdbc.jar:slf4j-api.jar:slf4j-nop.jar", "TinferServer"]
