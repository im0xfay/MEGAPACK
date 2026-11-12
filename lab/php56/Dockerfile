# Lab PHP 5.6 untuk Joomla 3.x lama.
#
# Kenapa perlu dibangun sendiri:
#  * Joomla <=3.4.x tidak bisa jalan di PHP 7 ('String' jadi reserved word -> fatal).
#  * Image resmi php:5.6-apache tidak menyertakan ext/mysqli dan apt-nya mati
#    (Debian stretch/jessie 404), jadi mysqli dikompilasi dari tarball php-src.
#  * CVE-2015-8562 hanya bekerja pada PHP <= 5.6.12 (perbaikan #70219: unserialize
#    berhenti pada error pertama) -> dibutuhkan versi PHP yang tepat.
#
# Pakai: docker build --build-arg PHP_VER=5.6.12 -t megapack-php5612 .
ARG PHP_VER=5.6.40
FROM php:${PHP_VER}-apache

ARG PHP_VER
ADD https://github.com/php/php-src/archive/refs/tags/php-${PHP_VER}.tar.gz /usr/src/php.tar.gz
RUN set -eux; \
    mkdir -p /usr/src/php; \
    tar -xzf /usr/src/php.tar.gz -C /usr/src/php --strip-components=1; \
    cd /usr/src/php/ext/mysqli; \
    phpize; \
    ./configure --with-mysqli=mysqlnd --with-php-config=/usr/local/bin/php-config; \
    make -j"$(nproc)"; \
    make install; \
    docker-php-ext-enable mysqli; \
    a2enmod rewrite; \
    rm -rf /usr/src/php /usr/src/php.tar.gz

RUN printf 'display_errors=0\noutput_buffering=4096\nerror_reporting=E_ALL & ~E_DEPRECATED & ~E_STRICT & ~E_NOTICE & ~E_WARNING\n' > /usr/local/etc/php/conf.d/zz-lab.ini
