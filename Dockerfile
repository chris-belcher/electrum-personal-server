FROM python
WORKDIR /
RUN git clone https://github.com/commerceblock/electrum-personal-server.git
WORKDIR /electrum-personal-server
ADD config.ini config.ini
RUN pip3 install .
CMD ["electrum-personal-server", "config.ini"]