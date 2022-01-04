from panic-nightly-test:latest

COPY powershell_lp_dbg powershell_lp_dbg
COPY powershell_lp powershell_lp

RUN apk add git gdb curl

RUN wget -q -O- https://github.com/hugsy/gef/raw/master/scripts/gef.sh | sh
RUN echo "set follow-fork-mode child" >> ~/.gdbinit
RUN echo "set detach-on-fork off" >> ~/.gdbinit

CMD ["gdb", "powershell_lp_dbg"]
