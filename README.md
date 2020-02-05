mqtt-gpio-sensor
================

A service, which publishes GPIO state to a MQTT topic. The program
will drop root permissions after opening the config file and the
gpiochip device. Afterwards it will use seccomp to sandbox itself.
It is suggested to use the systemd service file for adding additional
security arrangements, such as providing a read-only filesystem or
memory limits.

installation
============

```
# build binary
cargo build --release

# install binary
install -m755 target/release/mqtt-gpio-sensor /usr/local/sbin

# install systemd service
install -m644 data/mqtt-gpio-sensor@.service /etc/systemd/system
systemctl daemon-reload

# install config
install -m644 data/mqtt-gpio-sensor-example.cfg /etc

# enable autostart of the service
systemctl enable mqtt-gpio-sensor@example

# start the service now
systemctl start mqtt-gpio-sensor@example
```

License
=======

© 2020 Sebastian Reichel

ISC License

Permission to use, copy, modify, and/or distribute this software for
any purpose with or without fee is hereby granted, provided that the
above copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
