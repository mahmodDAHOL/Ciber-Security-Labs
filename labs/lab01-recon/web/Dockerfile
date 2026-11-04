FROM nginx:1.27-alpine
COPY site/ /usr/share/nginx/html/
COPY 50-flag.sh /docker-entrypoint.d/50-flag.sh
RUN sed -i 's/\r$//' /docker-entrypoint.d/50-flag.sh && chmod +x /docker-entrypoint.d/50-flag.sh
