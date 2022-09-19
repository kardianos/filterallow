FROM scratch

COPY filterallow filterallow

ENTRYPOINT ["/filterallow"]