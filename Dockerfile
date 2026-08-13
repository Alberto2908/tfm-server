# Use Eclipse Temurin JDK 21 as base image
FROM eclipse-temurin:21-jdk-alpine

# Set working directory
WORKDIR /app

# Copy Maven wrapper and pom.xml first for better caching
COPY .mvn/ .mvn/
COPY mvnw pom.xml ./

# Make mvnw executable
RUN chmod +x ./mvnw

# Download dependencies (this layer will be cached if pom.xml doesn't change)
RUN ./mvnw dependency:go-offline -B

# Copy source code
COPY src ./src

# Build the application
RUN ./mvnw clean package -DskipTests

# Expose port from environment variable (e.g. Render provides PORT)
EXPOSE ${PORT:-8080}

# Run the application (artifactId-version.jar)
CMD ["java", "-jar", "target/tfm.vulnerabilidades-0.0.1-SNAPSHOT.jar"]
