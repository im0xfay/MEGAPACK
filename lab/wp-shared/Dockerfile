FROM wordpress:6.7.1-php8.2-apache
RUN printf '<FilesMatch ".+\\.(phtml|php5|php7|phar|pht)$">\n  SetHandler application/x-httpd-php\n</FilesMatch>\n' \
    > /etc/apache2/conf-enabled/zz-shared-php.conf \
 && printf '<Directory /var/www/html/wp-content/uploads>\n  Options +Indexes\n  AllowOverride None\n  Require all granted\n  IndexIgnore .htaccess index.html\n</Directory>\n' \
    > /etc/apache2/conf-enabled/zz-shared-index.conf
