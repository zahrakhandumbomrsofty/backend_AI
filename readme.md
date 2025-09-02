Build
docker build -t medical-app:env .
RUN 
docker run -d --name medical-app -p 8080:8080 -v medical_app_instance:/app/instance medical-app:env