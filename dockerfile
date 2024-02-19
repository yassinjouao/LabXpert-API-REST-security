FROM maven:3.8.2-jdk-8
WORKDIR /app
COPY target/labx-0.0.1-SNAPSHOT.jar /app/labx-0.0.1-SNAPSHOT.jar
ENTRYPOINT ["java", "-jar", "labx-0.0.1-SNAPSHOT.jar"]