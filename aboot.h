#ifndef ABOOT_H
#define ABOOT_H

#include <stdbool.h>

#include "userfastboot_plugin.h"

char *get_device_id(void);
void aboot_register_commands(void);
void populate_status_info(void);
int set_device_state(enum device_state device_state, bool force);

#endif
