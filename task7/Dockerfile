FROM panic-nightly-test:latest 

# install git, gdb, and curl
RUN apk add git gdb curl
# install gef
RUN bash -c "$(curl -fsSL http://gef.blah.cat/sh)" 

# trigger network calls
RUN git clone https://github.com/hugsy/gef repo

# use patched binary to bypass network functionality
COPY patched_make /usr/bin/make

CMD ["gdb", "make"]
