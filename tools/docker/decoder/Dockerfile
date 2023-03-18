FROM maven:3.8-openjdk-11

# set up serving options
RUN mkdir -p /src
WORKDIR /src

# grab V2GDecoder
RUN git clone https://github.com/FlUxIuS/V2Gdecoder \
    && cd V2Gdecoder \
    && wget https://github.com/FlUxIuS/V2Gdecoder/releases/download/v1.1/V2Gdecoder-jar-with-dependencies.jar -O /src/decoder.jar

WORKDIR /src/V2Gdecoder
EXPOSE 9000/tcp
CMD ["java", "-jar", "/src/decoder.jar", "-w"]
