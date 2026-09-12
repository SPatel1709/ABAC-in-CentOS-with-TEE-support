/*
	Definitions for ABAC include/exclude path configuration
*/

#ifndef _ABAC_PATHCFG_H
#define _ABAC_PATHCFG_H

#include "abacfs.h"

struct abac_path_entry *parse_path_entries(char *buffer, int length);
void destroy_path_entries(struct abac_path_entry *head);
bool path_matches_entries(const char *path, struct abac_path_entry *head);

#endif /* _ABAC_PATHCFG_H */
