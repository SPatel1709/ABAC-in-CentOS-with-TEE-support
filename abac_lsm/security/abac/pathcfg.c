/*
	ABAC include/exclude path parsing helpers
*/

#include <linux/slab.h>
#include <linux/string.h>
#include "pathcfg.h"

static struct abac_path_entry *parse_line(char *buffer, int start, int end)
{
	int len = end - start;
	struct abac_path_entry *entry;

	if (len <= 0)
		return NULL;
	entry = kcalloc(1, sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return NULL;
	entry->path = kcalloc(len + 1, sizeof(char), GFP_KERNEL);
	if (!entry->path) {
		kfree(entry);
		return NULL;
	}
	strncpy(entry->path, buffer + start, len);
	entry->path[len] = '\0';
	return entry;
}

struct abac_path_entry *parse_path_entries(char *buffer, int length)
{
	int start = 0;
	int i;
	struct abac_path_entry *cursor = NULL;
	struct abac_path_entry *head = NULL;
	struct abac_path_entry *entry;

	if (!buffer || length < 1)
		return NULL;

	for (i = 0; i < length; i++) {
		if (buffer[i] != '\n')
			continue;
		entry = parse_line(buffer, start, i);
		if (entry) {
			if (cursor)
				cursor->next = entry;
			else
				head = entry;
			cursor = entry;
		}
		start = i + 1;
	}
	return head;
}

void destroy_path_entries(struct abac_path_entry *head)
{
	struct abac_path_entry *cursor = head;
	struct abac_path_entry *to_free;

	while (cursor != NULL) {
		to_free = cursor;
		cursor = cursor->next;
		kfree(to_free->path);
		kfree(to_free);
	}
}

bool path_matches_entries(const char *path, struct abac_path_entry *head)
{
	size_t prefix_len;

	while (head != NULL) {
		prefix_len = strlen(head->path);
		if (prefix_len > 0 && strncmp(path, head->path, prefix_len) == 0)
			return true;
		head = head->next;
	}
	return false;
}
