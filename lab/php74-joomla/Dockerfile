# Joomla 3.x butuh PHP <= 7.x; image lab lama (php:8.2) tidak jalan.
FROM php:7.4-apache
RUN docker-php-ext-install mysqli pdo_mysql >/dev/null 2>&1 && a2enmod rewrite >/dev/null 2>&1
# WAJIB: deprecation PHP 7.4 tercetak sebelum session start -> "headers already sent"
# -> Joomla "Application Instantiation Error: Failed to start the session".
RUN printf 'display_errors=0\nlog_errors=1\nerror_reporting=E_ALL & ~E_DEPRECATED & ~E_NOTICE & ~E_WARNING & ~E_STRICT\noutput_buffering=4096\n' \
    > /usr/local/etc/php/conf.d/zz-joomla-lab.ini
