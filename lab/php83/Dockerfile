# Lab PHP 8.3 untuk Joomla 6.x (6.0.3 rentan CVE-2026-48899, 6.1.3 patched).
# Joomla 6 mensyaratkan PHP >= 8.3; image lab php74/php56 tidak bisa dipakai.
# memory_limit 512M: Joomla 6 memuat bahasa/asset jauh lebih berat dari 3.x
# (128M -> "Allowed memory size exhausted" di LanguageHelper saat render admin).
FROM php:8.3-apache
RUN set -eux; \
    docker-php-ext-install -j"$(nproc)" mysqli; \
    a2enmod rewrite
RUN printf 'display_errors=0\noutput_buffering=4096\nmemory_limit=512M\npost_max_size=32M\nupload_max_filesize=32M\nerror_reporting=E_ALL & ~E_DEPRECATED & ~E_NOTICE & ~E_WARNING\n' > /usr/local/etc/php/conf.d/zz-lab.ini
