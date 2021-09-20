#include "socket_registry.h"

/* hash table */
static GHashTable *hash_table = NULL;
static pthread_mutex_t hash_table_mutex;

void free_data(gpointer data);


void registry_init() {
    hash_table = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, free_data);
    log_printf(LOG_VERBOSE, "registry: init %p \r\n", hash_table);
}

void registry_destroy() {
    if (hash_table) {
        log_printf(LOG_VERBOSE, "registry: destroy: removing all items from registry: %p \r\n", hash_table);

        g_hash_table_remove_all(hash_table);
        // according to the documentation g_hash_table_unref is thread safe
        g_hash_table_unref(hash_table);
    }
}

GHashTable* registry_get_table() {
    // according to the documentation g_hash_table_ref is thread safe
    return g_hash_table_ref(hash_table);
}

uint32_t registry_get_size() {
    guint size = 0;

    pthread_mutex_lock(&hash_table_mutex);
    size = g_hash_table_size(hash_table);
    pthread_mutex_unlock(&hash_table_mutex);

    return size;
}

void free_data(gpointer data) {
    log_printf(LOG_VERBOSE, "registry: free %p \r\n", data);
    if (data)
        free(data);
}

bool registry_add_socket(char *key, socket_container_t *packet) {
    bool res = false;

    pthread_mutex_lock(&hash_table_mutex);
    res = g_hash_table_insert(hash_table, key, packet);
    pthread_mutex_unlock(&hash_table_mutex);

    log_printf(LOG_VERBOSE, "registry: adding new: %s, %p %p \r\n", key, key, packet);

    return res;
}

bool registry_remove_socket(char *key) {
    bool res = false;

    pthread_mutex_lock(&hash_table_mutex);
    res = g_hash_table_remove(hash_table, key);
    pthread_mutex_unlock(&hash_table_mutex);

    log_printf(LOG_VERBOSE, "registry: removed: %s res: %d\r\n", key, res);

    return res;
}

socket_container_t* registry_get_socket(char *key) {
    socket_container_t *packet = NULL;

    pthread_mutex_lock(&hash_table_mutex);
    packet = g_hash_table_lookup(hash_table, key);
    pthread_mutex_unlock(&hash_table_mutex);

    log_printf(LOG_VERBOSE, "registry: getting: %s socket: %p\r\n", key, packet);

    return packet;
}

bool registry_update_socket(char *key, socket_container_t *packet) {
    bool res = false;

    pthread_mutex_lock(&hash_table_mutex);
    res = g_hash_table_replace(hash_table, key, packet);
    pthread_mutex_unlock(&hash_table_mutex);

    log_printf(LOG_VERBOSE, "registry: updating: %s socket: %p\r\n", key, packet);

    return res;
}
