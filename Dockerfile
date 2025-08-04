FROM openjdk:17-jdk-slim

# 设置工作目录
WORKDIR /app

# 复制JAR文件
COPY target/*.jar app.jar

# 创建非root用户
RUN addgroup --system spring && \
    adduser --system spring --ingroup spring && \
    chown spring:spring app.jar

# 切换到非root用户
USER spring:spring

# 暴露端口
EXPOSE 8081

# 运行应用
ENTRYPOINT ["java","-jar","app.jar"]
