FROM openjdk:17-jdk-slim
WORKDIR /app
COPY target/*.jar app.jar
RUN addgroup --system spring && adduser --system spring --ingroup spring
USER spring:spring
EXPOSE 8080
ENTRYPOINT ["java","-jar","/app.jar"]
