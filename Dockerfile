FROM node:22-alpine
WORKDIR /app
COPY package.json ./
COPY src ./src
COPY public ./public
COPY index.html ./
RUN mkdir /data && chown node:node /data
ENV NODE_ENV=production PORT=3000 DATA_FILE=/data/rapidpass.json
VOLUME /data
USER node
EXPOSE 3000
CMD ["node", "src/server.js"]
