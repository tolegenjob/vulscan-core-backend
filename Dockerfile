# Образ собирается из готового jar: сначала `./gradlew bootJar` (vulscan-kit берётся из mavenLocal).
FROM eclipse-temurin:21-jre
RUN apt-get update \
    && apt-get install -y --no-install-recommends wget \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system app && useradd --system --gid app --no-create-home app
WORKDIR /app
COPY build/libs/*.jar app.jar
USER app
ENV JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=70 -XX:+ExitOnOutOfMemoryError"
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --start-period=30s --retries=3 \
  CMD ["wget", "-qO-", "http://127.0.0.1:8080/actuator/health/readiness"]
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
