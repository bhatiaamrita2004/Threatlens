# Build stage: compile the jar with Maven and Java 17
FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /build
COPY pom.xml .
RUN mvn -q -B dependency:go-offline
COPY src ./src
RUN mvn -q -B clean package -DskipTests && cp target/backend-0.8.0.jar /build/app.jar

# Runtime stage: a small JRE image running as a non-root user
FROM eclipse-temurin:17-jre
RUN useradd -r -u 10001 threatlens
WORKDIR /app
COPY --from=build /build/app.jar app.jar
USER threatlens
EXPOSE 8080
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75", "-jar", "/app/app.jar"]