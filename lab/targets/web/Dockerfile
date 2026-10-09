# Laboratory target: Apache httpd 2.4.49
#
# Chosen because 2.4.49 carries CVE-2021-41773 (path traversal / RCE, CVSS 9.8)
# and CVE-2021-42013. Correlation for this exact version was measured during
# development: 81 CVE candidates via CPE, 0 via keyword search.
#
# Listens on 8080, NOT 80. Port 80 is on the protected-port list and can never
# be isolated, so a service there could not demonstrate exposure reduction.
FROM httpd:2.4.49

COPY targets/common/setup-ssh.sh /tmp/setup-ssh.sh
COPY build/authorized_keys /tmp/authorized_keys
RUN sh /tmp/setup-ssh.sh && rm -f /tmp/setup-ssh.sh

# Move Apache off the protected port so isolation is demonstrable.
RUN sed -i 's/^Listen 80$/Listen 8080/' /usr/local/apache2/conf/httpd.conf \
    && echo '<html><body><h1>CyberShield lab target</h1>' \
            '<p>Apache httpd 2.4.49 — authorized test environment only.</p>' \
            '</body></html>' > /usr/local/apache2/htdocs/index.html

COPY targets/common/entrypoint.sh /usr/local/bin/cybershield-entrypoint
RUN chmod +x /usr/local/bin/cybershield-entrypoint

EXPOSE 22 8080
ENTRYPOINT ["/usr/local/bin/cybershield-entrypoint"]
CMD ["httpd-foreground"]
