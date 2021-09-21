#ifndef SOCKET_REGISTRY_H
#define SOCKET_REGISTRY_H

/*
 * Wrapps socket registry
 * Currently uses Glib hash table implementation for sockets
 *
 * hash_table -> { key: char*, value: socket_container_t }
 * where key appears: "src_addr:src_port dst_addr:dst_port"
 *
 */

#include <stdbool.h>

#include <glib.h>

#include <pcap.h>

#include <pthread.h>

#include "include/net_headers.h"
#include "socket_container.h"

#include "logger.h"

void registry_init();
void registry_destroy();

GHashTable* registry_get_table();

bool registry_add_socket(char *key, socket_container_t *packet);

bool registry_remove_socket(char *key);

/*
 * returns socket_container_t * or NULL
 */
socket_container_t* registry_get_socket(char *key);

bool registry_update_socket(char *key, socket_container_t *packet);

uint32_t registry_get_size();

#endif // SOCKET_REGISTRY_H
