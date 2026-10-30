#ifndef HANDSHAKE_H
#define HANDSHAKE_H

#include <stdint.h>
#include "secure_crypto.h"

/*
 * is_server = 1: Device2 listens for Device1.
 * is_server = 0: Device1 connects to Device2.
 *
 * Returns 1 on success, 0 on failure.
 */
int device_handshake(
    int is_server,
    const char *server_ip,
    uint16_t port,
    unsigned char traffic_key[KEY_SIZE]
);

#endif